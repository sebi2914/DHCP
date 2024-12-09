server.o: server.c
	gcc -c -o server.o server.c

configread.o: configread.c
	gcc -c -o configread.o configread.c

dhcp_utils.o: dhcp_utils.c
	gcc -c -o dhcp_utils.o dhcp_utils.c

server: server.o configread.o dhcp_utils.o
	gcc -o server server.o configread.o dhcp_utils.o
	rm *.o