#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
foo ( char *arg )
{
	char	buf[1024];
	char	formatString[256];

	// A bit of a hack, to make things easier for the 64-bit addresses: we'll copy
	// the format string into a local buffer, and then skip the first 60 characters
	// of it when feeding it into snprintf(...)
	
	memcpy(formatString, arg, 256);
	snprintf(buf, sizeof(buf), &formatString[60]);

	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	printf ("Target5 running.\n");
	if (argc < 2)
	{
		fprintf(stderr, "target5: argc < 2\n");
		exit(EXIT_FAILURE);
	}
  
	foo ( argv[1] );
	return (0);
}
