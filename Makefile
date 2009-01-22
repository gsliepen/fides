all: fides

CFLAGS ?= -Wall -g -O0
LDFLAGS ?= -Wall -g -O0

fides: fides.o
	$(CXX) $(LDFLAGS) -o $@ $< -lbotan

%.o: %.cc %.h
	$(CXX) $(CFLAGS) -g -c -Wall -o $@ $<

clean:
	rm -f *.o fides
