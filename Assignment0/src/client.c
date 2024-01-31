#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>

#define SEND_BUFFER_SIZE 2048


/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
*/
int client(char *server_ip, char *server_port) {

    // define hints, specify connection info
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // get address info and put in result
    int status = getaddrinfo(server_ip, server_port, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 1;
    }

    // open socket
    int sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == -1) {
        perror("client fails to open socket");
        return 2;
    }

    // try connect with the server
    int connect_code = connect(sockfd, result->ai_addr, result->ai_addrlen);
    if (connect_code == -1) {
        perror("client fails to connect to the server");
        close(sockfd);
        return 3;
    }

    // continue to send the text until EOF
    char send_msg[SEND_BUFFER_SIZE];
    while (1) {
        int read_code = read(STDIN_FILENO, send_msg, SEND_BUFFER_SIZE);
        if (read_code == -1) {
            perror("fails to read input from stdin");
            close(sockfd);
            return 4;
        } else if (read_code == 0) {
            break;
        }
        int send_code = send(sockfd, send_msg, read_code, 0);
        if (send_code == -1) {
            perror("fails to send message to the server");
            close(sockfd);
            return 5;
        }
    }

    // close the socket
    close(sockfd);

    return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
*/
int main(int argc, char **argv) {
  char *server_ip;
  char *server_port;

  if (argc != 3) {
    fprintf(stderr, "Usage: ./client-c [server IP] [server port] < [message]\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
