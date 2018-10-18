#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    static unsigned char digest[16];
    static char hex_tmp[33];
    int i = 0;

    scanf("%s", &digest);
    for(i=0;i<16;i++){
        printf("%02hhx\n", digest[i]);
        sprintf(&hex_tmp[i*2], "%02x", digest[i]);
    }

    return 0;
}