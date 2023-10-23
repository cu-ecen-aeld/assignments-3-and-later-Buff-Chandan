CC=aarch64-none-linux-gnu-gcc

CFLAGS=-Wall -Werror

all : writer

writer: writer.o
	${CC} ${CFLAGS}  writer.c -o writer

clean:
	-rm -rf *.o writer
