#pragma once
#include <Windows.h>
#include <Zydis/Zydis.h>

class Debugger;

class ContextRestorer
{
private:
	CONTEXT original;
	Debugger* debugger;
public:
	ContextRestorer(Debugger* dbg);
	~ContextRestorer();
};

