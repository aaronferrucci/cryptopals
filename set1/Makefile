tests: test_base64 test1 test2 test3 test4 test5 test6 test7 test8

UTILS := ../utils
utils.o: $(UTILS)/utils.c $(UTILS)/utils.h
	gcc -c $(UTILS)/utils.c -I $(UTILS)

.PHONY: test_base64 
test_base64: test_decode64
	./test_decode64 "cGxlYXN1cmUu" "pleasure."
	./test_decode64 "c3VyZS4=" "sure."
	./test_decode64 "ZWFzdXJlLg==" "easure."
	./test_decode64 "c3VyZS4=" "sure."
	./test_decode64 \
	  "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" \
	  "I'm killing your brain like a poisonous mushroom"
	./test_decode64 \
	"TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=" \
	"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."

test_decode64.o: test_decode64.c $(UTILS)/utils.h
	gcc -c test_decode64.c -I $(UTILS)

test_decode64: test_decode64.o utils.o
	gcc -o test_decode64 test_decode64.o utils.o -lm

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

test6: challenge6
	./challenge6

test7: challenge7
	./challenge7

test8: challenge8
	./challenge8

challenge1.o: challenge1.c $(UTILS)/utils.h
	gcc -c challenge1.c -I $(UTILS)

challenge2.o: challenge2.c $(UTILS)/utils.h
	gcc -c challenge2.c -I $(UTILS)

challenge3.o: challenge3.c $(UTILS)/utils.h
	gcc -c challenge3.c -I $(UTILS)

challenge4.o: challenge4.c c4_data.h $(UTILS)/utils.h
	gcc -c challenge4.c -I $(UTILS)

challenge5.o: challenge5.c
	gcc -c challenge5.c

challenge6.o: challenge6.c c6_data.h $(UTILS)/utils.h
	gcc -c challenge6.c -I $(UTILS)

challenge7.o: challenge7.c c7_data.h $(UTILS)/utils.h
	gcc -c challenge7.c -I $(UTILS)

challenge8.o: challenge8.c c8_data.h $(UTILS)/utils.h
	gcc -c challenge8.c -I $(UTILS)

challenge1: challenge1.o utils.o
	gcc -o challenge1 challenge1.o utils.o -lm

challenge2: challenge2.o utils.o
	gcc -o challenge2 challenge2.o utils.o -lm

challenge3: challenge3.o utils.o
	gcc -o challenge3 challenge3.o utils.o -lm

challenge4: challenge4.o utils.o
	gcc -o challenge4 challenge4.o utils.o -lm

challenge5: challenge5.o
	gcc -o challenge5 challenge5.o

challenge6: challenge6.o utils.o
	gcc -o challenge6 challenge6.o utils.o -lm

challenge7: challenge7.o utils.o
	gcc -o challenge7 challenge7.o -lssl -lcrypto utils.o -lm

challenge8: challenge8.o utils.o
	gcc -o challenge8 challenge8.o utils.o -lm

clean:
	rm -f output.txt
	rm -f challenge1
	rm -f *.o
