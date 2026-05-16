// entry point that calls symbols defined in math.c
#include <windows.h>

int add(int a, int b);
int sub(int a, int b);
int mul(int a, int b);

static void print_int(HANDLE out, int n) {
    char buf[12];
    int i = 0;
    if (n == 0) { buf[i++] = '0'; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    for (int l = 0, r = i - 1; l < r; l++, r--) {
        char tmp = buf[l]; buf[l] = buf[r]; buf[r] = tmp;
    }
    buf[i++] = '\n';
    DWORD written;
    WriteFile(out, buf, i, &written, NULL);
}

void main(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    print_int(out, add(10, 5));
    print_int(out, sub(10, 5));
    print_int(out, mul(10, 5));
    ExitProcess(0);
}
