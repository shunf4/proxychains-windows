#include <stdio.h>
#include <locale.h>
#include <wchar.h>
#include <stdlib.h>

int main()
{
    const char* pstr = "\xe5\x86\xaf\xe8\x88\x9c";
    wchar_t xxx[100];
    setlocale(LC_ALL, "");
    printf(pstr);
    printf("\n");
    vswprintf(xxx, 100, L"%s", pstr);
    printf("%#02x\n", xxx[0]);

    exit(0);
}
