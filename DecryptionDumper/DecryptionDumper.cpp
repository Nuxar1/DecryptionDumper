#include <iostream>
#include "Debugger.h"
#include "Disassembler.h"
#include "PatternScanner.h"

int main()
{
	Debugger debug = Debugger();
	debug.Init("C:\\Program Files (x86)\\Call of Duty Modern Warfare\\ModernWarfare.exe");
	debug.Dump_Process();

	while (true)
	{
		Disassembler dis = Disassembler(&debug);
		dis.Init(debug.scanner->Find_Pattern("48 8b 04 c1 48 8b 1c 03 48 8b cb 48 8b 03 ff 90 98 00 00 00"));
		dis.Dump_ClientInfo();
		system("pause");
	}
}