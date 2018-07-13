tests: test_cbc128 test_ecb128 test9 test10 test11 test12 test13

UTILS := ../utils
utils.o: $(UTILS)/utils.c $(UTILS)/utils.h
	gcc -c $(UTILS)/utils.c -I $(UTILS)

test9: challenge9 
	./challenge9 > output.txt
	diff output.txt expect9.txt

test10: challenge10
	./challenge10 > output.txt
	diff output.txt expect10.txt

test11: challenge11
	./challenge11

test12: challenge12
	./challenge12

test13: challenge13
	./challenge13

test_ecb128: do_test_ecb128
	./do_test_ecb128 > output.txt
	cat output.txt

test_cbc128: do_test_cbc128
	./do_test_cbc128 > output.txt
	cat output.txt

challenge9.o: challenge9.c
	gcc -c challenge9.c

challenge9: challenge9.o
	gcc -o challenge9 challenge9.o

cbc_ecb128.o: cbc_ecb128.c
	gcc -c cbc_ecb128.c -I $(UTILS)

challenge10.o: challenge10.c $(UTILS)/utils.h
	gcc -c challenge10.c -I $(UTILS)

challenge11.o: challenge11.c $(UTILS)/utils.h
	gcc -c challenge11.c -I $(UTILS)

challenge12.o: challenge12.c $(UTILS)/utils.h
	gcc -c challenge12.c -I $(UTILS)

challenge13.o: challenge13.c $(UTILS)/utils.h
	gcc -g -c challenge13.c -I $(UTILS)

challenge10: challenge10.o utils.o cbc_ecb128.o
	gcc -o challenge10 challenge10.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

challenge11: challenge11.o utils.o cbc_ecb128.o
	gcc -o challenge11 challenge11.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

challenge12: challenge12.o utils.o cbc_ecb128.o
	gcc -o challenge12 challenge12.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

challenge13: challenge13.o utils.o cbc_ecb128.o
	gcc -o challenge13 challenge13.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

do_test_ecb128.o: do_test_ecb128.c $(UTILS)/utils.h
	gcc -c do_test_ecb128.c -I $(UTILS) -I ../set1

do_test_ecb128: do_test_ecb128.o utils.o cbc_ecb128.o
	gcc -o do_test_ecb128 do_test_ecb128.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

do_test_cbc128.o: do_test_cbc128.c $(UTILS)/utils.h
	gcc -c do_test_cbc128.c -I $(UTILS)

do_test_cbc128: do_test_cbc128.o utils.o cbc_ecb128.o
	gcc -o do_test_cbc128 do_test_cbc128.o utils.o cbc_ecb128.o -lssl -lcrypto -lm

clean:
	rm -f output.txt
	rm -f challenge?
	rm -f challenge??
	rm -f *.o
	rm -f do_test_ecb128

