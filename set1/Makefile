test1: challenge1 expect1.txt
	./challenge1 > output.txt
	diff output.txt expect1.txt

test2: challenge2 expect2.txt
	./challenge2 > output.txt
	diff output.txt expect2.txt

test3: challenge3
	./challenge3

test4: challenge4
	./challenge4

test5: challenge5
	./challenge5 > output.txt
	diff output.txt expect5.txt

utils.o: utils.c utils.h
	gcc -c utils.c

challenge1.o: challenge1.c
	gcc -c challenge1.c

challenge2.o: challenge2.c
	gcc -c challenge2.c

challenge3.o: challenge3.c utils.h
	gcc -c challenge3.c

challenge4.o: challenge4.c c4_data.h utils.h
	gcc -c challenge4.c

challenge5.o: challenge5.c
	gcc -c challenge5.c

challenge1: challenge1.o utils.o
	gcc -o challenge1 challenge1.o utils.o

challenge2: challenge2.o utils.o
	gcc -o challenge2 challenge2.o utils.o

challenge3: challenge3.o utils.o
	gcc -o challenge3 challenge3.o utils.o

challenge4: challenge4.o utils.o
	gcc -o challenge4 challenge4.o utils.o

challenge5: challenge5.o
	gcc -o challenge5 challenge5.o

clean:
	rm -f output.txt
	rm -f challenge1
	rm -f *.o
