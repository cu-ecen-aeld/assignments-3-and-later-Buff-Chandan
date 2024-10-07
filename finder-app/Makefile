CFLAGS=-Wall -Werror

all : writer

writer: writer.o
	$(CC) $(CFLAGS)  writer.c -o writer
	chmod +x writer
clean:
	-rm -rf *.o writer
