#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
*/
int server(char *server_port) {

   // define hints, specify connection info
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // open server sockets
    int servsock = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if (servsock == -1) {
        perror("server fails to open server socket");
        return 1;
    }

    // create data structure to store server address
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(server_port));
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // try binding 
    if (bind(servsock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("server fails to bind");
        close(servsock);
        return 2;
    }

    // infinity loop to connect with client
    while(1) {
    
    int listen_code = listen(servsock, QUEUE_LENGTH);
    if (listen_code  == -1) {
        perror("server fails to listen");
        close(servsock);
        return 3;
    }

    int clientfd = accept(servsock, NULL, NULL);
    if (clientfd == -1) {
        perror("server fails to accept client");
        close(servsock);
        return 4;
    }

    // inner infinite loop to receive data until it is consumed
    char recv_msg[RECV_BUFFER_SIZE];
    while (1) {
        int recv_code = recv(clientfd, recv_msg, RECV_BUFFER_SIZE, 0);
        if (recv_code == -1) {
            perror("server fails to receive sent info from client");
            close(clientfd);
            close(servsock);
            return 5;
        } else if (recv_code != 0) {
          if (recv_code > 0 && recv_code <= RECV_BUFFER_SIZE) {
            write(STDOUT_FILENO, recv_msg, recv_code);
            fflush(stdout);
          } else {
            perror("Invalid recv_code value");
            close(clientfd);
            close(servsock);
            return 6;
          }
        } else {
            break;
        }
    }

    // close the client connection 
    close(clientfd);

    }

    // close the server socket
    close(servsock);

    return 0;
}

/*
 * main():
 * Parse command-line arguments and call server function
*/
int main(int argc, char **argv) {
  char *server_port;

  if (argc != 2) {
    fprintf(stderr, "Usage: ./server-c [server port]\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
