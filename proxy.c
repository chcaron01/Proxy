/* Final Project -- Charlie Caron and Ryan Megathlin */

// To compile on mac: gcc -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o proxy -g proxy.c -lssl -lcrypto
// (Generates 2 warnings)

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

#define BUFSIZE 10000000
#define ENTRIES 100
#define MAX_HTTPS_CLIENTS 20
#define IPS 100
#define MAX_LINE 1000

typedef struct {
  char * key;
  char * value;
  int time_dead;
  int start_time;
  int bytes_len;
  struct timeval IPalive;
} entry;

typedef struct item
{
    int key;
    int fwdfd;
    char cache_key[MAX_LINE];
    SSL* ssl;
    SSL* fwdssl;
} item;

const item NULL_ITEM = { .key = -1,
                         .fwdfd = -1,
                         .cache_key = 0,
                         .ssl = NULL,
                         .fwdssl = NULL };

int send_to_server(char* buf, entry* cache, int* lru, int cacheEntry, int* bytes_read);
// Initializes values in each cache entry to NULL or 0
void initialize_cache(entry* cache);
// Initializes values in lru to index value
void initialize_lru(int* lru);
// Sets each entry child in cache to respective buffer
void add_entry(entry* cache, int cacheEntry, char* key, char* object, int max_age, int start_time, int bytes);
// Frees struct values for entry
void free_entry(entry* cache, int cacheEntry);
// Finds and returns an index in cache for which time has expired. Returns -1 otherwise.
int find_dead_times(entry* cache);
// For index to be replaced in cache, the entry is freed, new entry is added, and pushes index value to back
void update_LRU(int* lru, entry* cache, char* key, char* object, int max_age, int start_time, int bytes, int index);
// Pushes back specific index value to back of array (lru[0] is LRU, lru[length(lru) - 1] is MRU)
void pushback_LRU(int* lru, int index);
// Returns index if key is found in cache. Returns -1 if key not found
int find_entry(entry* cache, char* key);
// Handles each input line. For PUT: creates key, object, max-age buffers. Check if key exists. Check if cache is filled.
void handle_line(entry* cache, char* line, int* lru, int* filled, FILE* out);
// Check if there are expired times. Otherwise replace lru. For GET: check if key exists, fprintf object value
// Checks the cache or something

int check_cache(char* buf, entry* cache, int* lru, int* filled, int* bytes_read, char* ret_key);
// Reads all of https response and inserts it into the cache
int receive_https_response(item* cur_item, char* buf, entry* cache, int* lru, int* filled, int* bytes);

void print_cache(entry* cache);
// Called to handle a connect request. Does not handle the tunneling, only sets it up
int connect_init(char* buf, int clientfd);
// Creates the https connections to client and server. Inserts the SSL* structures into the items
int https_init(item* client, item* server);
// Removes an item from the fd_lookup and handles closing the fd
void remove_item(item* cur_item, item* fd_lookup, fd_set* active_fd_set);
// Inserts an item into the fd_lookup
int insert_item(item in_item, item* fd_lookup);
// Finds an item in the fd_lookup
item* find_item(int key, item* fd_lookup);
// Currently unused function to get sni without OpenSSL
char* get_sni(int fd);

int is_rate_limited(char* value, entry* cache, int* lru, int* filled, float rate);

// SSL helper functions

SSL_CTX* InitCTX();
SSL* SSLServerConnect(int sockfd, const char* SNI);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
int cert_cb(SSL *ssl, void* x509);
EVP_PKEY * generate_key();
X509 * generate_x509(EVP_PKEY * pkey, char * CN);


void init_openssl()
{ 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
}

void error(char *msg) {
  perror(msg);
}

int main(int argc, char **argv) {
  int parentfd; /* parent socket */
  int childfd; /* child socket */
  int clientlen; /* byte size of client's address */
  struct sockaddr_in serveraddr; /* server's addr */
  struct hostent *hostp; /* client host info */
  char *buf = malloc(BUFSIZE); /* message buffer */
  char *hostaddrp; /* dotted decimal host addr string */
  int optval; /* flag value for setsockopt */
  int n; /* message byte size */

  if (argc != 3) {
    fprintf(stderr, "usage: %s <port> <rate>\n", argv[0]);
    exit(1);
  }
  int portno = atoi(argv[1]);
  if (atof(argv[2]) <= 0) {
    fprintf(stderr, "usage: Rate must be greater than 0\n");
    exit(1);
  }
  float ratems = (1 / atof(argv[2])) * 1000000;
  fd_set active_fd_set, read_fd_set;
  int i;
  struct sockaddr_in clientname;

  entry* cache = (entry*)malloc(sizeof(entry) * ENTRIES);
  entry* rateLimiting = (entry*)malloc(sizeof(entry) * IPS);
  initialize_cache(cache);
  initialize_cache(rateLimiting);
  int* lru = (int*)malloc(sizeof(int) * ENTRIES);
  int* rateLRU = (int*)malloc(sizeof(int) * IPS);
  initialize_lru(lru);
  initialize_lru(rateLRU);
  int filled = 0;
  int rateFilled = 0;

  // Initializing lookup
  item* fd_lookup = malloc(sizeof(*fd_lookup) * 2*MAX_HTTPS_CLIENTS);
  for (int i = 0; i < 2*MAX_HTTPS_CLIENTS; i++) {
    item insert;
    insert.key = -1;
    bzero(insert.cache_key, MAX_LINE);
    fd_lookup[i] = insert;
  }

  init_openssl();

  parentfd = socket(AF_INET, SOCK_STREAM, 0);
  if (parentfd < 0) 
    error("ERROR opening socket");

  optval = 1;
  setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, 
         (const void *)&optval , sizeof(int));

  // build the server's Internet address
  bzero((char *) &serveraddr, sizeof(serveraddr));

  /* this is an Internet address */
  serveraddr.sin_family = AF_INET;

  /* let the system figure out our IP address */
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

  /* this is the port we will listen on */
  serveraddr.sin_port = htons((unsigned short)portno);
 
  // bind: associate the parent socket with a port 
  if (bind(parentfd, (struct sockaddr *) &serveraddr, 
       sizeof(serveraddr)) < 0) 
    error("ERROR on binding");

  if (listen(parentfd, 1) < 0)
    error("ERROR on listen");

  FD_ZERO (&active_fd_set);
  FD_SET (parentfd, &active_fd_set);

  clientlen = sizeof(clientname);
  while (1) {
    read_fd_set = active_fd_set;
    int select_val = select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
    if (select_val < 0)
      {
        perror ("select");
        exit (EXIT_FAILURE);
      }
    for (i = 0; i < FD_SETSIZE; ++i) {
      if (FD_ISSET (i, &read_fd_set)) {
        if (i == parentfd) {
          int new;
          new = accept (parentfd, (struct sockaddr *) &clientname,(socklen_t *) &clientlen);
          if (new < 0)
              {
                perror ("accept");
                exit (EXIT_FAILURE);
              }
            fprintf (stderr,
                     "Server: connect from host %s, port %hd.\n",
                     inet_ntoa (clientname.sin_addr),
                     ntohs (clientname.sin_port));
            FD_SET (new, &active_fd_set);
        }
        else {
          item* cur_item = find_item(i, fd_lookup);
          if (cur_item == NULL) { // Initial message from client
            hostp = gethostbyaddr((const char *)&clientname.sin_addr.s_addr, 
                                  sizeof(clientname.sin_addr.s_addr), AF_INET);
            if (hostp == NULL)
              error("ERROR on gethostbyaddr");
            hostaddrp = inet_ntoa(clientname.sin_addr);
            if (hostaddrp == NULL)
              error("ERROR on inet_ntoa\n");

            printf("server established connection with %s (%s)\n", hostp->h_name, hostaddrp);

            if (is_rate_limited(hostaddrp, rateLimiting, rateLRU, &rateFilled, ratems)) {
              error("RATE LIMITED");
              close(i); // QUESTION: Do we need to close i?
              FD_CLR (i, &active_fd_set);
            }
            else {
              bzero(buf, BUFSIZE);
              n = read(i, buf, BUFSIZE);
              if (n < 0) {
                error("ERROR reading from socket on first message");
                item it;
                it.key = i;
                remove_item(&it, fd_lookup, &active_fd_set);
                continue;
              }
              printf("server received %d bytes: %s", n, buf);
              int bytes_read = 0;

              // Checking if the received message is a CONNECT or GET request
              char* method = buf;
              char* end_method = strstr(buf, " ");
              *end_method = 0;
              if (strcmp(method, "CONNECT") == 0) {
                printf("Connect method received\n");
                *end_method = ' ';
                item new_client, new_server;

                int serverfd = connect_init(buf, i); // NEEDS WORK: client and server items input by reference
                if (!serverfd || serverfd == -1) {
                  error("ERROR with initializing the HTTPS connections");
                }
                // Insert the fds into the https array
                new_client.key = i;
                new_client.fwdfd = serverfd;
                new_client.ssl = NULL;
                new_client.fwdssl = NULL;
                if (!insert_item(new_client, fd_lookup))
                  error("No room for additional clients");
                new_server.key = serverfd;
                new_server.fwdfd = i;
                new_server.ssl = NULL;
                new_server.fwdssl = NULL;
                if (!insert_item(new_server, fd_lookup))
                  error("ERROR inserting client (server item) into the list");

                FD_SET (i, &active_fd_set);
                FD_SET (serverfd, &active_fd_set);
                // NEEDS WORK: How is a failed CONNECT handled?
              }
              else if (strcmp(method, "GET") == 0) {
                printf("Get method received\n");
                *end_method = ' ';
                int status = check_cache(buf, cache, lru, &filled, &bytes_read, NULL);
                if (status != -1)
                  printf("Buffer: %s\n", buf);
                  status = send_to_server(buf, cache, lru, status, &bytes_read);
                
                if (status)
                  n = write(i, buf, bytes_read);

                if (n <= 0) 
                  error("ERROR writing to socket");
                  
                  close(i); // QUESTION: Do we need to close i?
                  FD_CLR (i, &active_fd_set);
                }
              else {
                error("ERROR received unrecognized message method. Message was not forwarded");
              }
            }
          }
          else if (cur_item->ssl != NULL) { // is https, connection set
            printf("Reading on socket %d\n", cur_item->key);
            bzero(buf, BUFSIZE);

            n = SSL_read(cur_item->ssl, buf, BUFSIZE);
            if (n < 0) {
              error("ERROR reading HTTPS message");
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }
            else if (n == 0) { // Connection is done
              printf("Connection completed\n");
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }
            printf("Message read from socket\n");
            printf("Message:\n%s\n", buf);

            char* method = buf;
            char* end_method = strstr(buf, " ");
            int is_get = 0;
            int is_response = 0;
            if (end_method != NULL) {
              *end_method = 0;
              if (strcmp(method, "GET") == 0) {
                is_get = 1;
              }
              if (strncmp(method, "HTTP/", 5) == 0) {
                is_response = 1;
              }
              *end_method = ' ';
            }

            if (is_get) {
              printf("Message is a GET request\n");
              int bytes_read = 0;
              char key[1000];
              int status = check_cache(buf, cache, lru, &filled, &bytes_read, key);
              printf("Cache has been checked...");
              if (status != -1) { // GET request was not found in the cache
                printf("Request not found\n");
                n = SSL_write(cur_item->fwdssl, buf, n);
                if (n < 0) {
                  error("ERROR writing HTTPS message");
                  remove_item(cur_item, fd_lookup, &active_fd_set);
                  continue;
                }
                item* server_item = find_item(cur_item->fwdfd, fd_lookup);
                strcpy(server_item->cache_key, key);
              }
              else { // GET request was found in cache
                printf("Request was found\n");
                n = SSL_write(cur_item->ssl, buf, bytes_read);
                if (n < 0) {
                  error("ERROR writing HTTPS message");
                  remove_item(cur_item, fd_lookup, &active_fd_set);
                  continue;
                }
              }
            }
            else if (is_response) { // HTTPS response
              printf("Receiving https response...\n");
              int bytes_read = 0;
              int succ = receive_https_response(cur_item, buf, cache, lru, &filled, &bytes_read);
              if (!succ) {
                error("ERROR reading HTTPS response from server");
                remove_item(cur_item, fd_lookup, &active_fd_set);
                continue;
              }
              n = SSL_write(cur_item->fwdssl, buf, bytes_read);
              if (n < 0) {
                error("ERROR writing HTTPS response to client");
                remove_item(cur_item, fd_lookup, &active_fd_set);
                continue;
              }
              printf("Successfully cached and forwarded https response\n");
            }
            else { // a different type of HTTP method
              printf("Forwarding https message...\n");
              n = SSL_write(cur_item->fwdssl, buf, n);
              if (n < 0) {
                error("ERROR writing HTTPS message");
                remove_item(cur_item, fd_lookup, &active_fd_set);
                continue;
              }
              printf("Successfully forwarded https message\n");
            }
          }
          else { // is https but has not been initialized
            printf("Setting up https connection...");
            item* server_item = find_item(cur_item->fwdfd, fd_lookup);
            if (server_item == NULL) {
              error("ERROR server item not found in the data structure");
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }
            int succ = https_init(cur_item, server_item);
            if (!succ) {
              error("ERROR initializing the https connections");
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }
            printf("Complete\n");
          }
        }
      }
    }
  }
}

int receive_https_response(item* cur_item, char* buf, entry* cache, int* lru, int* filled, int* bytes) {
  int bytes_read = 0; //NEEDS WORK: is strlen okay?
  int target = 50000;
  int header_length = 0;
  int cl_found = 0;
  int n = strlen(buf);
  printf("Entering while loop with %d bytes read\n", n);
  while (n > 0 && target > bytes_read) {
    printf("Bytes read on previous iteration: %d\n", n);
    // NEEDS WORK: Needs to implement Transfer-Encoding: chunked
    if (!cl_found) {
      //Get CONTENT length
      char* cl = strstr(buf, "Content-Length: ");
      if (cl) {
        cl_found = 1;
        target = atoi(cl + 16);
        //Get HEADER length
        char* end_head = strstr(buf, "\r\n\r\n");
        *end_head = 0;
        header_length = strlen(buf) + 4;
        *end_head = '\r';
        target += header_length;
      }
    }
    bytes_read += n;
    n = SSL_read(cur_item->ssl, buf + bytes_read, BUFSIZE - bytes_read);
  }

  if (n < 0) {
    error("ERROR reading from socket for https response");
    return 0;
  }
  char* object = malloc(bytes_read);
  memcpy(object, buf, bytes_read);
  int max_age;
  char* time_left = strstr(buf, "Cache-Control: max-age=");
  int start_time = time(NULL);
  int bytes_len = bytes_read;
  *bytes = bytes_read;
  if (time_left) {
    max_age = atoi(time_left + 23) + start_time;
  }
  else {
    max_age = 3600 + start_time;
  }

  int rem_idx;
  int dead_time = find_dead_times(cache);
  // If cache is not filled
  if (*filled < ENTRIES) {
    (*filled)++;
    rem_idx = *filled - 1;
  }
  // If an entry's time has expired
  else if (dead_time != -1) {
    rem_idx = dead_time;
  }
  // Return lru
  else {
    rem_idx = lru[0];
  }

  update_LRU(lru, cache, cur_item->cache_key, object, max_age, start_time, bytes_read, rem_idx);
  printf("Echo from server: %s\n", buf);
  return 1;
}

int send_to_server(char* buf, entry* cache, int* lru, int cacheEntry, int* bytes){
    int sockfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;

    /* String manipulation getting hostname and directory */
    hostname = strstr(buf, "Host: ") + 6;
    char* end_host = strstr(hostname, "\r\n");
    *end_host = 0;
    char* port = strstr(hostname, ":");
    char* first_line = strstr(buf, hostname);
    char* directory = strstr(first_line, "/");
    char* end_dir = strstr(first_line, " ");
    *end_dir = 0;

    if (port) {
      portno = atoi(port + 1);
      *port = 0;
      server = gethostbyname(hostname);
      *port = ':';
    }
    else {
      portno = 80;
      server = gethostbyname(hostname);
    }
    char* key = malloc(strlen(hostname) + strlen(directory) + 1);
    strncpy(key, hostname, strlen(hostname));
    strncpy(key + strlen(hostname), directory, strlen(directory) + 1);
    *end_host = '\r';
    *end_dir = ' ';

    /* gethostbyname: get the server's DNS entry */
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        printf("send_to_server\n");
        return 0;
    }

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
        return 0;
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
      error("ERROR connecting");
      return 0;
    }

    /* send the message line to the server */
    n = write(sockfd, buf, strlen(buf));
    if (n < 0) {
      error("ERROR writing to socket");
      return 0;
    }

    /* print the server's reply */
    bzero(buf, BUFSIZE);
    int bytes_read = 0;
    int target = 4000;
    int header_length = 0;
    int cl_found = 0;
    do {
      n = read(sockfd, buf + bytes_read, BUFSIZE - bytes_read);
      if (!cl_found) {
        //Get CONTENT length
        char* cl = strstr(buf, "Content-Length: ");
        if (cl) {
          cl_found = 1;
          target = atoi(cl + 16);
          //Get HEADER length
          char* end_head = strstr(buf, "\r\n\r\n");
          *end_head = 0;
          header_length = strlen(buf) + 4;
          *end_head = '\r';
          target += header_length;
        }
      }
      bytes_read += n;
    }
    while (n > 0 && target > bytes_read);

    if (n < 0) {
      error("ERROR reading from socket");
      return 0;
    }
    char* object = malloc(bytes_read);
    memcpy(object, buf, bytes_read);
    int max_age;
    char* time_left = strstr(buf, "Cache-Control: max-age=");
    int start_time = time(NULL);
    int bytes_len = bytes_read;
    *bytes = bytes_read;
    if (time_left) {
      max_age = atoi(time_left + 23) + start_time;
    }
    else {
      max_age = 3600 + start_time;
    }
    
    update_LRU(lru, cache, key, object, max_age, start_time, bytes_read, cacheEntry);
    printf("Echo from server: %s\n", buf);
    close(sockfd);
    return 1;
}

int check_cache(char* buf, entry* cache, int* lru, int* filled, int* bytes_read, char* ret_key) {
  printf("In check_cache\n");
  print_cache(cache);
  /* String parsing gets hostname */
  char* hostname = strstr(buf, "Host: ") + 6;
  char* end_host = strstr(hostname, "\r\n");
  *end_host = 0;

  /* String parsing gets directory after hostname */
  char* first_line = strstr(buf, hostname);
  if (first_line == hostname) {
    first_line = strstr(buf, " ");
  }
  char* directory = strstr(first_line, "/");
  char* end_dir = strstr(first_line, " ");
  *end_dir = 0;
  
  char* key = malloc(strlen(hostname) + strlen(directory) + 1);
  strncpy(key, hostname, strlen(hostname));
  strncpy(key + strlen(hostname), directory, strlen(directory) + 1);
  if (ret_key != NULL)
    strcpy(ret_key, key);
  // Return back to original
  *end_host = '\r';
  *end_dir = ' ';
  printf("Searching for entry...");
  int key_exists = find_entry(cache, key);
  free(key);
  int dead_time = find_dead_times(cache);
  // If key is in cache
  if (key_exists != -1) {
    if (cache[key_exists].time_dead < time(NULL)) {
      return key_exists;
    }
    else {
      bzero(buf, BUFSIZE);
      char age[10];
      sprintf(age, "%ld", time(NULL) - cache[key_exists].start_time);
      char age_header[17];
      strcpy(age_header, "Age: ");
      strcat(age_header, age);
      strcat(age_header, "\r\n");
      char* endline = strstr(cache[key_exists].value, "\r\n");
      *endline = 0;
      *bytes_read = cache[key_exists].bytes_len + strlen(age_header);
      int endl_len = strlen(cache[key_exists].value);
      memcpy(buf, cache[key_exists].value, endl_len);
      memcpy(buf + endl_len, "\r\n", 2);
      memcpy(buf + endl_len + 2, age_header, strlen(age_header));
      memcpy(buf + endl_len + 2 + strlen(age_header), endline + 2, cache[key_exists].bytes_len - (endl_len + 2));
      *endline = '\n';
      pushback_LRU(lru, key_exists);
      return -1;
    }
  }
  // If cache is not filled
  else if (*filled < ENTRIES) {
    (*filled)++;
    return *filled - 1;
  }
  // If an entry's time has expired
  else if (dead_time != -1) {
    return dead_time;
  }
  // Return lru
  else {
    return lru[0];
  }
}

int is_rate_limited(char* value, entry* cache, int* lru, int* filled, float rate) {
  char* key = malloc(strlen(value) + 1);
  strncpy(key, value, strlen(value));
  // Return back to original
  int key_exists = find_entry(cache, key);

  // If key is in cache
  if (key_exists != -1) {
    struct timeval currTime;
    gettimeofday(&currTime, NULL);
    int deltatime = (currTime.tv_sec - cache[key_exists].IPalive.tv_sec)  * 1000000 + (currTime.tv_usec - cache[key_exists].IPalive.tv_usec);
    if (deltatime < rate) {
      pushback_LRU(lru, key_exists);
      return 1;
    }
    else {
      cache[key_exists].IPalive = currTime;
      pushback_LRU(lru, key_exists);
      return 0;
    }
  }
  // If cache is not filled
  else if (*filled < IPS) {
    (*filled)++;
    cache[(*filled) - 1].key = key;
    gettimeofday(&(cache[(*filled) - 1].IPalive), NULL);
    return 0;
  }
  // Return lru
  else {
    free(cache[lru[0]].key);
    cache[lru[0]].key = key;
    gettimeofday(&(cache[lru[0]].IPalive), NULL);
    pushback_LRU(lru, lru[0]);
    return 0;
  }
}

int connect_init(char* buf, int clientfd) {
    int serverfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;

    /* String manipulation getting hostname and port */
    hostname = buf + 8;
    char* end_host = strstr(hostname, ":");
    *end_host = 0;
    char* port = end_host+1;
    char* end_port = strstr(port, " ");
    *end_port = 0;

    if (port) {
      portno = atoi(port);
      *end_port = ' ';
    }
    else {
      portno = 443; // HTTPS port
    }
    server = gethostbyname(hostname);
  
    /* gethostbyname: get the server's DNS entry */
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        printf("connect_init\n");
        return -1;
    }

    *end_host = ':';

    // Make connection with server

    /* socket: create the socket */
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        error("ERROR opening socket");
        return -1;
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    if (connect(serverfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
      error("ERROR connecting");
      return -1;
    }

    printf("Connected to requested server\n");

    // Report to the client that connection was successful
    char* okay_response = "HTTP/1.1 200 OK\r\n\r\n";

    n = write(clientfd, okay_response, strlen(okay_response));
    if (n < 0) {
      error("ERROR writing to client");
      return -1;
    }

    printf("Okay response sent to client\n");

    return serverfd;
}

int https_init(item* client, item* server) {
  // NEEDS WORK: validate all steps of process, return 0 on failure
  SSL_CTX *ctx = create_context();
  //configure_context(ctx);
  client->ssl = SSL_new(ctx);
  SSL_set_cert_cb(client->ssl, cert_cb, server);
  SSL_set_fd(client->ssl, client->key);
  if (SSL_accept(client->ssl) <= 0) {
    error("ERROR unable to complete the TLS handshake with client");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  client->fwdssl = server->ssl;
  server->fwdssl = client->ssl;
  return 1;
}

int cert_cb(SSL *ssl, void* server) {
  item* serverItem = (item*) server;
  const char* sni =  SSL_get_servername(ssl, SSL_get_servername_type(ssl));
  serverItem->ssl = SSLServerConnect(serverItem->key, sni);
  if (serverItem->ssl == NULL) {
    error("ERROR unable to complete the TLS handshake with server");
    return 0;
  }
  X509* cert_server = SSL_get_peer_certificate(serverItem->ssl);
  if (cert_server) {
    X509_NAME *subj_server = X509_get_subject_name(cert_server);
    int pos_server = X509_NAME_get_index_by_NID(subj_server, NID_commonName, 0);
    printf("%d\n", pos_server);
    if (pos_server == -1) {
      printf("Client: No common name...? Common name not modified\n");
      return 0;
    }
    else {
      X509_NAME_ENTRY *e_server = X509_NAME_get_entry(subj_server, pos_server);
      ASN1_STRING *x = X509_NAME_ENTRY_get_data(e_server);
      char* cn = ASN1_STRING_data(x);
      printf("\nCOMMON NAME:%s\n", cn);
      EVP_PKEY * cert_key = generate_key();
      X509* certificate = generate_x509(cert_key, cn);

      if (!SSL_use_certificate(ssl, certificate)) {
        printf("Inserting certificate failed\n");
        exit(1);
      }
      if (!SSL_use_PrivateKey(ssl, cert_key)){
        printf("Inserting key failed\n");
        exit(1);
      }
      return 1;
    }
  }
  
  return 0;
}

void remove_item(item* cur_item, item* fd_lookup, fd_set* active_fd_p) {
  printf("Remove item has been called\n");
  if (cur_item->ssl != NULL) {
    SSL_shutdown(cur_item->ssl);
    SSL_free(cur_item->ssl);
  }

  if (cur_item->fwdssl != NULL) {
    SSL_shutdown(cur_item->fwdssl);
    SSL_free(cur_item->fwdssl);
  }

  if (cur_item->key != -1) {
    FD_CLR (cur_item->key, active_fd_p);
    close(cur_item->key);
  }

  if (cur_item->fwdfd != -1) {
    FD_CLR (cur_item->fwdfd, active_fd_p);
    close(cur_item->fwdfd);
    item* rem_item = find_item(cur_item->fwdfd, fd_lookup);
    if (rem_item != NULL) {
      *rem_item = NULL_ITEM;
    }
  }
  *cur_item = NULL_ITEM;
  printf("Remove item returning\n");
}

int insert_item(item in_item, item* fd_lookup) {
  for (int i = 0; i < 2*MAX_HTTPS_CLIENTS; i++) {
    if (fd_lookup[i].key == -1) {
      fd_lookup[i] = in_item;
      return 1;
    }
  }
  return 0;
}

item* find_item(int key, item* fd_lookup) {
  for (int i = 0; i < 2*MAX_HTTPS_CLIENTS; i++) {
    if (fd_lookup[i].key == key) {
      return &fd_lookup[i];
    }
  }
  return NULL;
}

void initialize_cache(entry* cache) {
  for (int i = 0; i < ENTRIES; i++){
      cache[i].key = NULL;
      cache[i].value = NULL;
      cache[i].time_dead = 0;
  }
}

void initialize_lru(int* lru) {
  for (int i = 0; i < ENTRIES; i++) {
    lru[i] = i;
  }
}

void add_entry(entry* cache, int cacheEntry, char* key, char* object, int max_age, int start_time, int bytes){
  cache[cacheEntry].time_dead = max_age;
  cache[cacheEntry].key = key;
  cache[cacheEntry].value = object;
  cache[cacheEntry].start_time = start_time;
  cache[cacheEntry].bytes_len = bytes;
}

void free_entry(entry* cache, int cacheEntry){
  if (cache[cacheEntry].key) {
      free(cache[cacheEntry].key);
    }
  if (cache[cacheEntry].value) {
    free(cache[cacheEntry].value);
  }
}

void update_LRU(int* lru, entry* cache, char* key, char* object, int max_age, int start_time, int bytes, int index){
  free_entry(cache, index);
  add_entry(cache, index, key, object, max_age, start_time, bytes);
  pushback_LRU(lru, index);
}

void pushback_LRU(int* lru, int index) {
  for (int i = 0; i < ENTRIES; i++){
    if (lru[i] == index) {
      int mru = lru[i];
      for (int j = i; j < ENTRIES - 1; j++) {
        lru[j] = lru[j+1];
        lru[j+1] = mru;
      }
      break;
    }
  }
}
  
int find_dead_times(entry* cache) {
  for (int i = 0; i < ENTRIES; i++){
    if (time(NULL) > cache[i].time_dead) {
      return i;
    }         
  }
  return -1;
}

int find_entry(entry* cache, char* key) {
  for (int i = 0; i < ENTRIES; i++){
    if (cache[i].key != NULL) {
      if (!strcmp(cache[i].key, key)){
        return i;
      }
    }         
  }
  return -1;
}

// SSL helper functions

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL* SSLServerConnect(int sockfd, const char* SNI) {
  (void)SNI;
  // NEEDS WORK: We need to validate the server certificate, because the client doesn't get to
  SSL_CTX* ctx = InitCTX();
  SSL* ssl = SSL_new(ctx);
  SSL_set_tlsext_host_name(ssl, SNI);
  SSL_set_fd(ssl, sockfd);
  if (SSL_connect(ssl) == -1) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  else {
    return ssl;
  }
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_cipher_list(ctx, "ALL");

    /* Set the key and cert */
    if ( SSL_CTX_use_certificate_file(ctx, "root-cert/proxy-cert.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, "root-cert/proxy.keys", SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

EVP_PKEY * generate_key() {
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }
    
    /* Generate the RSA key and assign it to pkey. */
    FILE *fp = fopen("./root-cert/private/EMEN.key", "r");
    RSA * rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, "elephantmen");
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* The key has been generated, return it. */
    return pkey;
}

EVP_PKEY * get_CA() {
  EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }
    
    /* Generate the RSA key and assign it to pkey. */
    FILE *fp = fopen("./authorityCerts/myCA.key", "r");
    RSA * rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, "onedove");
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* The key has been generated, return it. */
    return pkey;
}

X509 * generate_x509(EVP_PKEY * pkey, char * CN) {
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    X509 * CAx509 = X509_new();
    if(!x509)
    {
        return NULL;
    }
    
    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);
    
    /* We want to copy the subject name to the issuer name. */
    BIO *i = BIO_new(BIO_s_file());

    if ((BIO_read_filename(i, "./authorityCerts/myCA.pem") <= 0) || ((CAx509 = PEM_read_bio_X509_AUX(i, NULL, NULL, NULL)) == NULL)) {
        return NULL;
    }

    X509_NAME * name = X509_get_subject_name(CAx509);
    
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) CN, -1, -1, 0);
    
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    
    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, get_CA(), EVP_sha1()))
    {
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

void print_cache(entry* cache) {
  for (int i = 0; i < ENTRIES; i++) {
    if (cache[i].key) {
      printf("CACHE ENTRY: %s\n", cache[i].key);
    }
  }
}