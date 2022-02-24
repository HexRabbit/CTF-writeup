all: exploit

exploit: exploit.c userfaultfd.c
	gcc exploit.c userfaultfd.c -Wall -o $@

clean:
	rm -f exploit
