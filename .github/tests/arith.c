// tests basic arithmetic and multiple function calls without CRT
#include <windows.h>

static int add(int a, int b) { return a + b; }
static int mul(int a, int b) { return a * b; }

static void print_int(HANDLE out, int n) {
    char buf[12];
    int i = 0;
    if (n == 0) { buf[i++] = '0'; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    // reverse
    for (int l = 0, r = i - 1; l < r; l++, r--) {
        char tmp = buf[l]; buf[l] = buf[r]; buf[r] = tmp;
    }
    buf[i++] = '\n';
    DWORD written;
    WriteFile(out, buf, i, &written, NULL);
}

void main(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    print_int(out, add(3, 4));
    print_int(out, mul(6, 7));
    print_int(out, add(100, 23));
    ExitProcess(0);
}
