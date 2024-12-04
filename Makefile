server.o: server.c
	gcc -c -o server.o server.c

configread.o: configread.c
	gcc -c -o configread.o configread.c

server: server.o configread.o
	gcc -o server server.o configread.o
	rm *.o