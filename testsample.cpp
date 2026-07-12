#include <windows.h>

/* Linker -> advanced: Entry Point main
* Linker -> input: Ignore All Default Libraries, Yes (/NODEFAULTLIB)
* Linker -> System: SubSystem Windows
* C/C++ -> Code Generation: Disable security check, disable C++ exceptions, disable CFG
*/

void main() {
    MessageBoxA(NULL, "HELLO", "HELO", MB_OK | MB_ICONINFORMATION);
    ExitProcess(0);
}
