#include <iostream>
#include <conio.h> // for _getch
#include "Debugger.h"
#include "Disassembler.h"
#include "PatternScanner.h"

enum Game
{
	none,
	ModernWarfare,
	Vanguard,
	ModernWarfare2,
};

int main()
{
	Debugger debug = Debugger();
	Game selected_game = Game::none;

	while (true)
	{
		printf("Select game: \n\t1: Modern Warfare\n\t2: Vanguard\n\t3: Modern Warfare 2\n");
		selected_game = (Game)((int)_getch() - '0');
		switch (selected_game)
		{
		case ModernWarfare:
			printf("Dumping Modern Warfare.\n");
			debug.Init("C:\\Program Files (x86)\\Call of Duty Modern Warfare\\ModernWarfare.exe");
			break;
		case Vanguard:
			printf("Dumping Modern Vanguard.\n");
			debug.Init("C:\\Program Files (x86)\\Call of Duty Vanguard\\Vanguard.exe");
			break;
		case ModernWarfare2:
			printf("Dumping Modern Warfare 2.\n");
			debug.Init("C:\\Program Files (x86)\\Steam\\steamapps\\\common\\Call of Duty HQ\\cod.exe");
			break;
		default:
			system("cls");
			printf("Not a valid input.\n");
			//std::cin.ignore(INT_MAX, '\n');
			continue;
			break;
		}
		debug.Dump_Process();

		system("cls");
		Disassembler dis = Disassembler(&debug);
		switch (selected_game) {
		case ModernWarfare:
		case ModernWarfare2:
			dis.Dump_ClientInfo_MW(debug.scanner->Find_Pattern("48 8B 4C 24 ? BA ? ? ? ? 0F B7"));
			dis.Dump_ClientBase(debug.scanner->Find_Pattern("4C 8B 83 ? ? ? ? 90 C6 44 24 ? ? 0F B6 44 24"));
			break;
		case Vanguard:
			dis.Dump_ClientInfo_Vanguard(debug.scanner->Find_Pattern("48 8B 83 ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6 4C 24 ?? C0"));
			dis.Dump_ClientBase(debug.scanner->Find_Pattern("FF 90 ? ? ? ? 48 8B 13 48 8B CB 48 89 85 ? ? ? ? 8B 87 ? ? ? ? 89 44 24 48 4C 8B 82 ? ? ? ? 8B D0 41 FF D0 "));
			break;
		}
		dis.Dump_BoneBase(debug.scanner->Find_Pattern("0F BF B4 ?? ?? ?? ?? ?? 89 ?? 24 ?? 85"));
		dis.Dump_BoneIndex(debug.scanner->Find_Pattern("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00"));

		if (selected_game == Game::ModernWarfare || selected_game == Game::ModernWarfare2)
			dis.Dump_Offsets_MW();
		std::getchar();
	}
}