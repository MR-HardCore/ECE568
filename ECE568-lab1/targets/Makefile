# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb
LDFLAGS :=
LDLIBS :=

# sources
sources := target1.c target2.c target3.c target4.c target5.c target6.c
support := stackSetup.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets) $(support:.c=.o)

target1 : target1.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target1 $(support:.c=.o) target1.o

target2 : target2.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target2 $(support:.c=.o) target2.o
	
target3 : target3.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target3 $(support:.c=.o) target3.o

target4 : target4.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target4 $(support:.c=.o) target4.o

target5 : target5.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target5 $(support:.c=.o) target5.o

target6 : tmalloc.o target6.o $(support:.c=.o)
	$(CC) $(CFLAGS) -lpthread -o target6 tmalloc.o $(support:.c=.o) target6.o

clean:
	$(RM) $(targets) $(sources:.c=.o) $(support:.c=.o) tmalloc.o

