dnsmake: 
	gcc -Wall dnsspoof.c -o dnsspoof -lnet -lpcap -pthread
