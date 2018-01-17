#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
foo ( char *arg, char *out )
{
	strcpy(out, arg);
	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	t = 2;
	char	buf[96];

	printf ("Target1 running.\n");

	if (argc != t)
	{
		fprintf(stderr, "target1: argc != 2\n");
		exit(EXIT_FAILURE);
	}

	foo ( argv[1], buf );
	return (0);
}
