test: challenge1
	./challenge1 > output.txt
	diff output.txt expected_output.txt

utils.o: utils.c utils.h
	gcc -c utils.c

challenge1.o: challenge1.c
	gcc -c challenge1.c

challenge1: challenge1.o utils.o
	gcc -o challenge1 challenge1.o utils.o

clean:
	rm -f output.txt
	rm -f challenge1
	rm -f *.o
