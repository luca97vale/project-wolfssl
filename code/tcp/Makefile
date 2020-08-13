# TLS Examples Makefile
CC       = gcc
LIB_PATH = /usr/local
CFLAGS   = -Wall -I$(LIB_PATH)/include -pthread -lncurses
LIBS     = -L$(LIB_PATH)/lib -lm

# option variables
DEBUG_FLAGS     = -g -DDEBUG
DEBUG_INC_PATHS = -MD
OPTIMIZE        = -Os


# Options
#CFLAGS+=$(DEBUG_FLAGS)
CFLAGS+=$(OPTIMIZE)
#CFLAGS+=$(QAT_FLAGS)
#LIBS+=$(QAT_LIBS)
#LIBS+=$(STATIC_LIB)

# OS / CPU Detection
OS_DET=UNKNOWN
CPU_DET=UNKNOWN
ifeq ($(OS),Windows_NT)
    OS_DET=WIN32
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        CPU_DET=AMD64
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            CPU_DET=AMD64
        endif
        ifeq ($(PROCESSOR_ARCHITECTURE),x86)
            CPU_DET=IA32
        endif
    endif
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        OS_DET=LINUX
    endif
    ifeq ($(UNAME_S),Darwin)
        OS_DET=OSX
    endif
    UNAME_P := $(shell uname -p)
    ifeq ($(UNAME_P),x86_64)
        CPU_DET=AMD64
    endif
    ifneq ($(filter %86,$(UNAME_P)),)
        CPU_DET=IA32
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        CPU_DET=ARM
    endif
endif

.PHONY: clean all

all: client-tcp server-tcp-threaded

client-tcp: client-tcp.c minitalk.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

server-tcp-threaded: server-tcp-threaded.c minitalk.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	-rm -f *.o $(objects) 
	-rm -f server-tcp-threaded client-tcp
