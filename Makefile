# Compilează server.o din server.c
server.o: server.c
	gcc -c -o server.o server.c

# Compilează configread.o din configread.c
configread.o: configread.c
	gcc -c -o configread.o configread.c

# Creează executabilul server din server.o și configread.o
server: server.o configread.o
	gcc -o server server.o configread.o
