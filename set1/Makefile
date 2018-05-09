test: challenge1
	./challenge1 > output.txt
	diff output.txt expected_output.txt

challenge1: challenge1.c
	gcc -o challenge1 challenge1.c

clean:
	rm -f output.txt
	rm -f challenge1
