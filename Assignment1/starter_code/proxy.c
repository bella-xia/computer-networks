#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

const int QUEUE_LENGTH = 10;
const int MAX_REQ_LEN = 65535;
const char *BAD_REQUEST_MSG = "HTTP/1.0 400 Bad Request\r\n\r\n";
const char *NOT_IMPLEMENTED_MSG = "HTTP/1.0 501 Not Implemented\r\n\r\n";

void print_full_char_rep(const char *c, int len)
{
  printf("Full string representation:\n");
  for (int i = 0; i < len; ++i)
  {
    switch (c[i])
    {
    case '\n':
      printf("\\n");
      break;
    case '\r':
      printf("\\r");
      break;
    case '\t':
      printf("\\t");
      break;
    default:
      putchar(c[i]);
    }
  }
  printf("\n");
}

char *send_to_server(char *server_ip, int server_port, char *data)
{
  char recv_msg[MAX_REQ_LEN];
  int server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock == -1)
  {
    perror("proxy fails to open server socket");
    return NULL;
  }
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  server_addr.sin_addr.s_addr = inet_addr(server_ip);

  if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
  {
    perror("proxy fails to connect to server");
    close(server_sock);
    return NULL;
  }

  if (send(server_sock, data, strlen(data), 0) == -1)
  {
    perror("proxy fails to send data to server");
    close(server_sock);
    return NULL;
  }
  int recv_code = recv(server_sock, recv_msg, MAX_REQ_LEN, 0);
  if (recv_code == -1)
  {
    perror("proxy fails to receive response from server");
  }
  else if (recv_code == 0)
  {
    printf("Server closed connection\n");
  }
  else
  {
    recv_msg[recv_code] = '\0';
  }

  close(server_sock);
  char *return_str = (char *)malloc(recv_code + 1);
  strcpy(return_str, recv_msg);
  return return_str;
}

int check_recv_msg(char *recv_msg, int recv_length)
{
  if (recv_length < 4)
  {
    return 0;
  }
  else if (strncmp(recv_msg + (recv_length - 4), "\r\n\r\n", 4) == 0)
  {
    return 1;
  }
  return 0;
}

void handle_client(int clientfd)
{
  char recv_msg[MAX_REQ_LEN];
  int recv_length = 0;
  // int continuing = 1;
  // while (continuing)
  // {
  recv_length = 0;
  while (!check_recv_msg(recv_msg, recv_length))
  {
    int recv_code = recv(clientfd, recv_msg + recv_length, MAX_REQ_LEN - recv_length, 0);
    // continuing = (recv_code == 0) ? 0 : 1;
    if (recv_code == -1)
    {
      perror("server fails to receive sent info from client");
      close(clientfd);
    }
    recv_length += recv_code;
  }
  //   print_full_char_rep(recv_msg, recv_code);
  //   printf("%.*s\n", recv_code, recv_msg);
  struct ParsedRequest *new_request = ParsedRequest_create();
  int parse_code = ParsedRequest_parse(new_request, recv_msg, recv_length);
  if (parse_code < 0)
  {
    int send_code = send(clientfd, BAD_REQUEST_MSG, strlen(BAD_REQUEST_MSG), 0);
    if (send_code == -1)
    {
      perror("proxy fails to send data to server");
    }
  }
  else
  {
    // get the server ip and port
    struct hostent *host_info = gethostbyname(new_request->host);
    if (host_info == NULL)
    {
      int send_code = send(clientfd, BAD_REQUEST_MSG, strlen(BAD_REQUEST_MSG), 0);
      if (send_code == -1)
      {
        perror("proxy fails to send data to server");
      }
    }
    else if (strcmp(new_request->method, "GET") != 0)
    {
      int send_code = send(clientfd, NOT_IMPLEMENTED_MSG, strlen(NOT_IMPLEMENTED_MSG), 0);
      if (send_code == -1)
      {
        perror("proxy fails to send data to server");
      }
    }
    else
    {
      if (strcmp(new_request->version, "HTTP/1.0") != 0)
      {
        new_request->version = "HTTP/1.0";
      }
      ParsedHeader_set(new_request, "Host", new_request->host);
      ParsedHeader_set(new_request, "Connection", "close");
      char *server_ip = inet_ntoa(*((struct in_addr *)host_info->h_addr_list[0]));
      int server_port = (new_request->port == NULL) ? 80 : atoi(new_request->port);

      // get message
      int server_len = ParsedRequest_totalLen(new_request);
      char *server_msg = (char *)malloc(server_len + 1);
      if (ParsedRequest_unparse(new_request, server_msg, server_len) < 0)
      {
        printf("unparse failed\n");
        return;
      }
      server_msg[server_len] = '\0';

      char *server_response = send_to_server(server_ip, server_port, server_msg);
      if (server_response != NULL)
      {
        int send_code = send(clientfd, server_response, strlen(server_response), 0);
        if (send_code == -1)
        {
          perror("proxy fails to send data to server");
        }
      }
      else
      {
        perror("No response from the server");
      }
      free(server_response);
      free(server_msg);
    }
  }
  ParsedRequest_destroy(new_request);
  // }
}
/* TODO: proxy()
 * Establish a socket connection to listen for incoming connections.
 * Accept each client request in a new process.
 * Parse header of request and get requested URL.
 * Get data from requested remote server.
 * Send data to the client
 * Return 0 on success, non-zero on failure
 */
int proxy(char *proxy_port)
{

  // define hints, specify connection info
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  // open server sockets
  int servsock = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
  if (servsock == -1)
  {
    perror("server fails to open server socket");
    return 1;
  }

  // create data structure to store server address
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(atoi(proxy_port));
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // try binding
  if (bind(servsock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
  {
    perror("server fails to bind");
    close(servsock);
    return 2;
  }

  // infinity loop to connect with client

  int listen_code = listen(servsock, QUEUE_LENGTH);
  if (listen_code == -1)
  {
    perror("server fails to listen");
    close(servsock);
    return 3;
  }

  while (1)
  {
    struct sockaddr_in client;
    int clientfd, c = sizeof(struct sockaddr_in);

    clientfd = accept(servsock, (struct sockaddr *)&client, (socklen_t *)&c);
    if (clientfd == -1)
    {
      perror("server fails to accept client");
      close(servsock);
      return 4;
    }

    // fork
    pid_t pid = fork();
    if (pid == -1)
    {
      // fork fails
      perror("unable to fork");
      close(clientfd);
      // close(servsock);
      return 5;
    }
    else if (pid == 0)
    {
      // close(servsock);
      handle_client(clientfd);
      close(clientfd);
      exit(0);
    }
    close(clientfd);
    // waitpid(-1, NULL, WNOHANG);
  }
  // close the server socket
  close(servsock);

  return 0;
}

int main(int argc, char *argv[])
{
  char *proxy_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./proxy <port>\n");
    exit(EXIT_FAILURE);
  }

  proxy_port = argv[1];
  return proxy(proxy_port);
}
