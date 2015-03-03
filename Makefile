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
ifeq ($(PLATFORM),FreeBSD)
	OBJS += eyefi-freebsd.o
endif

eyefi-config: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm -f eyefi-config core  $(OBJS) cscope*

eyefi-chdk.o: eyefi-config.h 
eyefi-config.o: eyefi-config.h
eyefi-linux.o: eyefi-config.h 
eyefi-unix.o: eyefi-config.h
md5.o: eyefi-config.h
sha1.o: eyefi-config.h
