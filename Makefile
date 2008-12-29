fides: fides.o
	$(CC) -o $@ $<

%.o: %.c
	$(CC) -c -o $@ $<
