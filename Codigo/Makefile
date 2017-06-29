all: server client

server: ecc_server.c
	gcc -I/home/daniel/mbedtls-2.4.2/include -L/home/daniel/mbedtls-2.4.2/library -O0 -ggdb3 ecc_server.c -o server -lmbedtls -lmbedcrypto

client: ecc_client.c
	gcc -I/home/daniel/mbedtls-2.4.2/include -L/home/daniel/mbedtls-2.4.2/library -O0 -ggdb3 ecc_client.c -o client -lmbedtls -lmbedcrypto

clean:
	rm -rf server client
