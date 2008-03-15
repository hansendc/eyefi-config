CC=gcc
CFLAGS=-g -Wall

eyefi-config: eyefi-config.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm eyefi-config core 


