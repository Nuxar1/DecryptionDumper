#include <iostream>
#include "Debugger.h"
#include "Disassembler.h"
#include "PatternScanner.h"

int main()
{
	Debugger debug = Debugger();
	//debug.Init("C:\\Program Files (x86)\\Call of Duty Vanguard\\Vanguard.exe");
	debug.Init("C:\\Program Files (x86)\\Call of Duty Modern Warfare\\ModernWarfare.exe");
	//debug.Dump_Process();

	while (true)
	{
		system("cls");
		Disassembler dis = Disassembler(&debug);
		dis.Dump_ClientInfo(debug.scanner->Find_Pattern("48 8B 04 C1 48 8B 1C 03 48 8B CB 48 8B 03 FF 90 98 00 00 00", true));
		dis.Dump_ClientBase(debug.scanner->Find_Pattern("48 8B 83 ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6", true));
		dis.Dump_BoneBase(debug.scanner->Find_Pattern("0F BF B4 ?? ?? ?? ?? ?? 89 ?? 24 ?? 85"));
		dis.Dump_BoneIndex(debug.scanner->Find_Pattern("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00"));
		std::getchar();
	}
}