// tests WriteFile + GetStdHandle + ExitProcess imports from kernel32
#include <windows.h>

void main(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(out, "hello world\n", 12, &written, NULL);
    ExitProcess(0);
}
