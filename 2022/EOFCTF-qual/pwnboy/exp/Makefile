all: exploit.gb

# -Wl-yt25 for MBC5
# https://gbdk-2020.github.io/gbdk-2020/docs/api/docs_rombanking_mbcs.html
exploit.gb: exploit.c
	./gbdk/bin/lcc -mgbz80:gb -Wl-yt25 $< -o $@

clean:
	rm -f exploit.gb
