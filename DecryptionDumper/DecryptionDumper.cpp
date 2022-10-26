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
		if (selected_game == Game::ModernWarfare) {
			dis.Dump_Offsets_MW();
			dis.Dump_ClientInfo_MW(debug.scanner->Find_Pattern("FF 90 90 00 00 00 84 C0 0F 84 ? ? ? ? 48 8B 1D ? ? ? ? C6 44 24 50 ? 0F B6 44 24 50 4C 8D 05 ? ? ? ? C0 C8 ? 0F B6 C0 4C 89 44 24 78")); // OG , FF 90 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6 44 24
		}
		else if (selected_game == Game::Vanguard) {
			dis.Dump_ClientInfo_Vanguard(debug.scanner->Find_Pattern("48 8B 83 ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6 4C 24 ?? C0"));
		}
		dis.Dump_ClientBase(debug.scanner->Find_Pattern("48 8B 83 68 F8 0A 00 C6 44 24 58 ? 0F B6 4C 24 58 C0 C1 ? 0F B6 C9 65 48 8B 19 48 F7 D3 48 85 C0 0F 84 ? ? ? ? 48 8B CB 48 C1 E9 ? 83 E1 ? 48 83 F9 ? 0F 87 ? ? ? ? 48 8D 15 ? ? ? ? 8B 8C 8A 4C A8 06 02"));
		dis.Dump_BoneBase(debug.scanner->Find_Pattern("0F BF B4 ?? ?? ?? ?? ?? 89 ?? 24 ?? 85"));
		dis.Dump_BoneIndex(debug.scanner->Find_Pattern("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00"));
		std::getchar();
	}
}