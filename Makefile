all : netfilter_test

netfilter_test: netfilter_test.o
	gcc -o netfilter_test netfilter_test.o -lnetfilter_queue

netfilter_test.o:
	gcc -c -o netfilter_test.o netfilter_test.c -lnetfilter_queue

clean:
	rm -f netfilter_test
	rm -f *.o

