server.o: server.c
	gcc -c -o server.o server.c
server: server.o
	gcc -o server server.o