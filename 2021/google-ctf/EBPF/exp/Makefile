TARGET := exploit
all: $(TARGET)

%: %.c
	@musl-gcc $< -static -o $@ 
	@strip $@

clean:
	@rm -f $(TARGET)
