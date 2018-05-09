test: set1
	./set1 > output.txt
	diff output.txt expected_output.txt

set1: set1.c
	gcc -o set1 set1.c

clean:
	rm -f output.txt
	rm -f set1
