wimax: wimax.o
	gcc -o wimax wimax.o -lusb-1.0

wimax.o: wimax.c
	gcc -c wimax.c

clean:
	rm wimax wimax.o
