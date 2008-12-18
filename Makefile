#CC=$(CROSS_COMPILE)gcc -march=armv5te -mtune=xscale
#-march=armv5te  
#-marm
CFLAGS=-g -Wall

OBJS = eyefi-config.o eyefi-unix.o sha1.o md5.o

PLATFORM := $(shell uname -s)

ifeq ($(PLATFORM),Linux)
	OBJS += eyefi-linux.o
endif
ifeq ($(PLATFORM),Darwin)
	OBJS += eyefi-osx.o
endif

eyefi-config: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -static -o $@

clean:
	rm eyefi-config core  $(OBJS) cscope*


