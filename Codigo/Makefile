all: server client

server: ecc_server.c
	gcc -O0 -ggdb3 ecc_server.c -o server -lmbedtls -lmbedcrypto

client: ecc_client.c
	gcc -O0 -ggdb3 ecc_client.c -o client -lmbedtls -lmbedcrypto

clean:
	rm -rf server client
