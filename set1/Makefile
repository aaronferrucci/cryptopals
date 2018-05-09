test1: challenge1 expect1.txt
	./challenge1 > output.txt
	diff output.txt expect1.txt

test2: challenge2 expect2.txt
	./challenge2 > output.txt
	diff output.txt expect2.txt

utils.o: utils.c utils.h
	gcc -c utils.c

challenge1.o: challenge1.c
	gcc -c challenge1.c

challenge2.o: challenge2.c
	gcc -c challenge2.c

challenge1: challenge1.o utils.o
	gcc -o challenge1 challenge1.o utils.o

challenge2: challenge2.o utils.o
	gcc -o challenge2 challenge2.o utils.o

clean:
	rm -f output.txt
	rm -f challenge1
	rm -f *.o
