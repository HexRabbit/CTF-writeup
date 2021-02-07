EXPS = smep_exp smap_exp
all: $(EXPS)

$(EXPS): % : %.c
	@gcc $@.c -Wall -static -masm=intel -o $@

clean:
	@rm -f $(EXPS)
