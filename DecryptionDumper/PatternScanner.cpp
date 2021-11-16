#include "PatternScanner.h"
#include "Debugger.h"
#include <intrin.h>


PatternScanner::PatternScanner(Debugger* dbg) : debugger(dbg) {
	Init();
}

#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))
#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define PEFHDROFFSET(a) (PIMAGE_FILE_HEADER)((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(ptr) (PIMAGE_SECTION_HEADER)((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)))

std::vector<uintptr_t> FindPattern(byte* pBaseAddress, byte* pbMask, const char* pszMask, size_t nLength)
{
	std::vector<uintptr_t> out;
	out.reserve(30);

	auto DataCompare = [](const auto* pData, const auto* mask, const auto* cmask, auto chLast, size_t iEnd) -> bool {
		if (pData[iEnd] != chLast) return false;
		for (size_t i = 0; i <= iEnd; ++i) {
			if (cmask[i] == 'x' && pData[i] != mask[i]) {
				return false;
			}
		}

		return true;
	};

	auto iEnd = strlen(pszMask) - 1;
	auto chLast = pbMask[iEnd];

	for (size_t i = 0; i < nLength - strlen(pszMask); ++i) {
		if (DataCompare(pBaseAddress + i, pbMask, pszMask, chLast, iEnd)) {
			out.push_back(i + 0x1000);
		}
	}

	return out;
}

PIMAGE_SECTION_HEADER PatternScanner::getCodeSection(LPVOID lpHeader)
{
	PIMAGE_FILE_HEADER pfh = PEFHDROFFSET(lpHeader);
	if (pfh->NumberOfSections < 1)
	{
		return NULL;
	}
	PIMAGE_SECTION_HEADER psh = SECHDROFFSET(lpHeader);
	return psh;
}

void PatternScanner::Init()
{
	LPVOID lpHeader = malloc(0x1000);
	ReadProcessMemory(debugger->h_proc, (LPCVOID)debugger->base_address, lpHeader, 0x1000, NULL);

	DWORD delta = 0x1000;
	LPCVOID lpStart = 0; //0
	nSize = 0;// 0x548a000;

	PIMAGE_SECTION_HEADER SHcode = getCodeSection(lpHeader);
	if (SHcode)
	{
		nSize = SHcode->Misc.VirtualSize;
		delta = SHcode->VirtualAddress;
		lpStart = ((LPBYTE)debugger->base_address + delta);
	}
	lpCodeSection = malloc(nSize);
	ReadProcessMemory(debugger->h_proc, lpStart, lpCodeSection, nSize, NULL);
}

uintptr_t PatternScanner::Find_Pattern(const char* pattern, bool last, uint32_t rIndex, uintptr_t offset, uintptr_t base_offset, uintptr_t pre_base_offset)
{
	size_t l = strlen(pattern);
	PBYTE patt_base = static_cast<PBYTE>(_alloca(l >> 1));
	PBYTE msk_base = static_cast<PBYTE>(_alloca(l >> 1));
	PBYTE pat = patt_base;
	PBYTE msk = msk_base;
	l = 0;
	while (*pattern) {
		if (*pattern == ' ')
			pattern++;
		if (!*pattern)
			break;
		if (*(PBYTE)pattern == (BYTE)'\?') {
			*pat++ = 0;
			*msk++ = '?';
			pattern += ((*(PWORD)pattern == (WORD)'\?\?') ? 2 : 1);
		}
		else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
			pattern += 2;
		}
		l++;
	}
	*msk = 0;
	*pat = 0;

	if (nSize) {
		auto r = FindPattern((byte*)lpCodeSection, (byte*)patt_base, (const char*)msk_base, nSize);
		if (!r.size())
			return 0;

		uintptr_t ret;
		if (last)
			ret = r[r.size() - 1] + pre_base_offset;
		else
			ret = r[rIndex] + pre_base_offset;

		if (offset == 0) {
			return ret + debugger->base_address + base_offset;
		}
		DWORD dRead = debugger->read<DWORD>(debugger->base_address + ret + offset);
		ret = ret + dRead + base_offset;
		return ret;
	}
	else
		return 0;
}
