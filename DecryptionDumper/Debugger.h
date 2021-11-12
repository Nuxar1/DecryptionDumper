#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <Zydis/Zydis.h>
class PatternScanner;

enum class DebugStatus
{
	suspended,
	interrupted, //thread reported debug event.
	none,
};
enum class DebugFlag
{
	step_over,
	step_out,
	step_single,
	none,
};

class Debugger
{
private:
	ZydisDecoder decoder;
	ZydisFormatter formatter;


	DebugStatus debug_status;
	DebugFlag debug_flags;

public:
	uintptr_t base_address;
	uint32_t process_id;
	uint32_t thread_id;
	HANDLE h_thread;
	HANDLE h_proc;
	PatternScanner* scanner;
	bool exception_hit;
private:
	bool Load_File(std::string exe_path);
	bool DispatchDebugEvent(const DEBUG_EVENT& debugEvent);
	bool OnCreateProcessEvent(const CREATE_PROCESS_DEBUG_INFO* pInfo);
	bool OnExceptionEvent(const EXCEPTION_DEBUG_INFO* pInfo);
public:
	Debugger();

	bool Init(std::string exe_path);
	void Dump_Process();
	CONTEXT GetContext();
	bool SetContext(CONTEXT* context);
	bool SetRIP(uintptr_t address);
	bool SetTrapFlag();
	uintptr_t SingleStep();
	uintptr_t StepIn();
	uintptr_t StepOver();
	void Run();

	template<typename T>
	T read(uintptr_t address) {
		T buffer;
		ReadProcessMemory(h_proc, (LPVOID)address, &buffer, sizeof(T), 0);
		return buffer;
	}
	template<typename T>
	void write(uintptr_t address, T value) {
		WriteProcessMemory(h_proc, (LPVOID)address, &value, sizeof(T), 0);
	}
	template<typename T>
	bool read_array(uintptr_t address, T* buffer, size_t size) {
		ReadProcessMemory(h_proc, (LPVOID)address, buffer, sizeof(T) * size, 0);
		return buffer;
	}
	template<typename T>
	void write_array(uintptr_t address, T* value, size_t size) {
		WriteProcessMemory(h_proc, (LPVOID)address, value, sizeof(T) * size, 0);
	}
};

