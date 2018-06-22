tests: test_base64

test10: challenge10
	./challenge10 > output.txt
	diff output.txt expect10.txt

test9: challenge9 
	./challenge9 > output.txt
	diff output.txt expect9.txt

test_ecb128: do_test_ecb128
	./do_test_ecb128 > output.txt
	cat output.txt

challenge9.o: challenge9.c
	gcc -c challenge9.c

challenge9: challenge9.o
	gcc -o challenge9 challenge9.o

cbc_ecb128.o: cbc_ecb128.c
	gcc -c cbc_ecb128.c -I ../set1

challenge10.o: challenge10.c
	gcc -c challenge10.c -I ../set1

UTILS := ../set1
utils.o: $(UTILS)/utils.c
	gcc -c $(UTILS)/utils.c -I $(UTILS)

challenge10: challenge10.o utils.o cbc_ecb128.o
	gcc -o challenge10 challenge10.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

do_test_ecb128.o: do_test_ecb128.c
	gcc -c do_test_ecb128.c -I ../set1

do_test_ecb128: do_test_ecb128.o utils.o cbc_ecb128.o
	gcc -o do_test_ecb128 do_test_ecb128.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

clean:
	rm -f output.txt
	rm -f challenge?
	rm -f challenge??
	rm -f *.o
