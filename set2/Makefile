tests: test_base64

test9: challenge9 
	./challenge9 > output.txt
	diff output.txt expect9.txt

utils.o: utils.c utils.h
	gcc -c $(UTILS_DIR)/utils.c

challenge9.o: challenge9.c
	gcc -c challenge9.c

challenge9: challenge9.o
	gcc -o challenge9 challenge9.o


clean:
	rm -f output.txt
	rm -f challenge9
	rm -f *.o
