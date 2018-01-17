/*
	stackSetup.c

	Initialization code for ECE568 lab assignments.  Ensures that the stack of the
	"target" thread is starting from a fixed, known address.  The code that would
	normally be in main() should be in a function called lab_main() instead.

	Please send any bug reports to Courtney Gibson <gibson@eecg.utoronto.ca>
*/

#define	STACK_LOCATION	0x020200000
#define	STACK_SIZE	( 128 * 1024 )

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

extern int lab_main ( int argc, char * argv[] );

struct main_args {

	int	argc;
	char **	argv;
};

void *
lab_main_thread ( void * p )
{
	struct main_args *	main_args = (struct main_args *)p;
	int *			rc = NULL;

	// Allocate space on the heap to store the lab_main() return value
	rc = (int *) malloc ( sizeof ( int ) );
	assert ( rc != NULL );

	// Call lab_main(), passing in argc and argv
	*rc = lab_main ( main_args->argc, main_args->argv );
	return ( rc );
}

int
main ( int argc, char * argv[] )
{
	size_t			stackSize = STACK_SIZE;
	void *			targetStack = (void *)STACK_LOCATION;
	int			pageSize = getpagesize ();
	void *			mmap_result = NULL;
	pthread_t		lab_main_thread_id;
	pthread_attr_t		pthread_attr;
	int			rc = 0;
	struct main_args	args = { argc , argv };
	int *			lab_main_return = NULL;

	// Check that our target stack size is an integer multiple of the system page size
	stackSize += pageSize - ( stackSize % pageSize );

	// Allocate a new stack at a fixed location
	mmap_result = mmap(targetStack, ( stackSize + pageSize ),
			PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_FIXED|MAP_PRIVATE, -1,
			(off_t)0);
	assert ( mmap_result != MAP_FAILED );

	// Create a new pthread to run lab_main()
	rc = pthread_attr_init ( &pthread_attr );
	assert ( rc == 0 );
	rc = pthread_attr_setstack ( &pthread_attr, targetStack, stackSize );
	assert ( rc == 0 );
	rc = pthread_create ( &lab_main_thread_id, &pthread_attr, lab_main_thread, (void *)&args);
	assert ( rc == 0 );

	// Wait for the thread running lab_main() to exit, and capture its return value
	rc = pthread_join ( lab_main_thread_id, (void **)&lab_main_return );
	if ( rc ) return ( -1 );
	return ( *lab_main_return );
}
