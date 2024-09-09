CC=gcc

CFLAGS=-Wall -Werror

all : writer

writer: writer.o
	$(CROSS_COMPILE)$(CC) $(CFLAGS)  writer.c -o writer

clean:
	-rm -rf *.o writer
