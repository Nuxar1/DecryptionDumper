This is my decryption dumper I made over the last week. It's not been tested for a long time (mainly because I can't test myself lol) but I will keep updating it a bit.

It works similar to the dumper moleskn has made (attach debugger then step though) so big thanks for that @moleskn. However, you probably have to admit yourself the code is a mess so i decided to fix it up.
Adding to that I changed the logic for detecting the end of decryption, I added a new (imo better) way of tracing the needed instructions and also added stack tracing (which could be improved further).

Summary of how it works:
  1. It loads the decryption routine into a buffer while keeping track of the indices where every other register was last modified while saving the current register that's overwritten for the next instructions.
  2. It finds the last time the encrypted register (and then decrypted) is referenced and starts to trace every instruction that's needed in order to get a valid result. It does that by checking what register is read and then recursively continue for these registers.
  3. In the end it goes through all needed instruction and prints them. If the stack is referenced, it looks at where instruction that stack location is set and gets the instruction that sets it. Then a local variable gets created which then gets assigned to the value of the stack location. (you can just make it 1 line, but I had planned on making it possible to trace stack values that required multiple instructions)

It also supports dumping decryption for Vanguard, but I didn't bother adding offsets for that game.

Released on: https://www.unknowncheats.me/forum/call-of-duty-modern-warfare/478869-decryption-offset-dumper.html
