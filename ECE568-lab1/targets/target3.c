#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
bar ( char * arg, char * targ, int ltarg )
{
	int	len, i;

	len = strlen(arg);
	if (len > ltarg) len = ltarg;

	targ += strlen(targ);
	for (i = 0; i <= len; i++) targ[i] = arg[i];

	return (0);
}

int
foo ( char * arg )
{
	char	buf[64];

	sprintf ( buf, "AAAA" );
	bar ( arg, buf, 88 );

	return (0);
}

int
lab_main ( int argc, char * argv[] )
{
	int	t = 2;

	printf ( "Target3 running.\n" );
	if (argc != t)
	{
		fprintf ( stderr, "target3: argc != 2\n" );
		exit ( EXIT_FAILURE );
	}

	foo ( argv[1] );
  
	return (0);
}
