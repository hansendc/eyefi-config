CC=gcc
CFLAGS=-g -Wall

OBJS = eyefi-config.o sha1.o md5.o

eyefi-config: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm eyefi-config core  $(OBJS)


