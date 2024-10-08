TARGET := writer

all: $(TARGET)

$(TARGET): writer.c
	$(CC) $< -o $@
	chmod +x $@
clean:
	-rm -rf $(TARGET) 

.PHONY: clean
