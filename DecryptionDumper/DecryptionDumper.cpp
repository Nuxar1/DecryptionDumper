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
};

int main()
{
	Debugger debug = Debugger();
	Game selected_game = Game::none;

	while (true)
	{
		printf("Select game: \n\t1: Modern Warfare\n\t2: Vanguard\n");
		selected_game = (Game)((int)_getch() - '0');
		switch (selected_game)
		{
		case ModernWarfare:
			debug.Init("C:\\Program Files (x86)\\Call of Duty Modern Warfare\\ModernWarfare.exe");
			break;
		case Vanguard:
			debug.Init("C:\\Program Files (x86)\\Call of Duty Vanguard\\Vanguard.exe");
			break;
		default:
			system("cls");
			printf("Not a valid input.\n");
			//std::cin.ignore(INT_MAX, '\n');
			continue;
			break;
		}
		//debug.Dump_Process();

		system("cls");
		Disassembler dis = Disassembler(&debug);
		if (selected_game == Game::ModernWarfare)
			dis.Dump_ClientInfo_MW(debug.scanner->Find_Pattern("48 8B 04 C1 48 8B 1C 03 48 8B CB 48 8B 03 FF 90 98 00 00 00", true));
		else if (selected_game == Game::Vanguard)
			dis.Dump_ClientInfo_Vanguard(debug.scanner->Find_Pattern("FF 90 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6 44 24", true));
		dis.Dump_ClientBase(debug.scanner->Find_Pattern("48 8B 83 ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6", true));
		dis.Dump_BoneBase(debug.scanner->Find_Pattern("0F BF B4 ?? ?? ?? ?? ?? 89 ?? 24 ?? 85"));
		dis.Dump_BoneIndex(debug.scanner->Find_Pattern("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00"));
		std::getchar();
	}
}