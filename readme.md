## wlnk
A lightweight, open-source PE (Windows) linker.<br>
Licensed under MIT License.

### why only windows?
the main problem with linkers on windows - dependencies.<br>
for example, `ld` itself can only be downloaded via **msys2**, which brings along a bunch of dependencies. and the official linker `link.exe` from **msvc**, as you already know, also brings a lot of stuff with it, and on top of that, you need to download the heavy **visual studio** for msvc.
<br><br>
and that's why it's windows only, because on macos/linux either the linker is already built-in, or it can be installed with a single command.