/* Final Project -- Charlie Caron and Ryan Megathlin */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>

#define BUFSIZE 10000000
#define ENTRIES 10
#define MAX_HTTPS_CLIENTS 20

typedef struct {
  char * key;
  char * value;
  int time_dead;
  int start_time;
  int bytes_len;
} entry;

typedef struct item
{
    int key;
    int fwdfd;
    int is_started;
} item;

const item NULL_ITEM = { .key = -1,
                         .fwdfd = -1,
                         .is_started = false };

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
// Check if there are expired times. Otherwise replace lru. For GET: check if key exists, fprintf object value
void handle_line(entry* cache, char* line, int* lru, int* filled, FILE* out);
int check_cache(char* buf, entry* cache, int* lru, int* filled, int* bytes_read, int childfd);
// Called to handle a connect request. Does not handle the tunneling, only sets it up
int connect_init(char* buf, int clientfd);
// Removes an item from the fd_lookup and handles closing the fd
void remove_item(item* cur_item, item* fd_lookup, fd_set* active_fd_set);
// Inserts an item into the fd_lookup
int insert_item(item in_item, item* fd_lookup);
// Finds an item in the fd_lookup
item* find_item(int key, item* fd_lookup);

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

  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }
  int portno = atoi(argv[1]);
  fd_set active_fd_set, read_fd_set;
  int i;
  struct sockaddr_in clientname;

  entry* cache = (entry*)malloc(sizeof(entry) * ENTRIES);
  initialize_cache(cache);
  int* lru = (int*)malloc(sizeof(int) * ENTRIES);
  initialize_lru(lru);
  int filled = 0;

  // Initializing lookup
  item* fd_lookup = malloc(sizeof(*fd_lookup) * 2*MAX_HTTPS_CLIENTS);
  for (int i = 0; i < 2*MAX_HTTPS_CLIENTS; i++) {
    item insert;
    insert.key = -1;
    fd_lookup[i] = insert;
  }

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
          if (cur_item->key == -1) {
            hostp = gethostbyaddr((const char *)&clientname.sin_addr.s_addr, 
                                  sizeof(clientname.sin_addr.s_addr), AF_INET);
            if (hostp == NULL)
              error("ERROR on gethostbyaddr");
            hostaddrp = inet_ntoa(clientname.sin_addr);
            if (hostaddrp == NULL)
              error("ERROR on inet_ntoa\n");

            printf("server established connection with %s (%s)\n", hostp->h_name, hostaddrp);

            bzero(buf, BUFSIZE);
            n = read(i, buf, BUFSIZE);
            if (n < 0) 
              error("ERROR reading from socket");
            printf("server received %d bytes: %s", n, buf);
            int bytes_read = 0;
            // NEEDS WORK: Assumes only explicit CONNECT or GET requests get here. Valid?

            // Checking if the received message is a CONNECT or GET request
            char* method = buf;
            char* end_method = strstr(buf, " ");
            *end_method = 0;
            if (strcmp(method, "CONNECT") == 0) {
              printf("Connect method received\n");
              *end_method = ' ';
              int serverfd = connect_init(buf, i);
              // Insert the fds into the https array
              item new_client, new_server;
              new_client.key = i;
              new_client.fwdfd = serverfd;
              new_client.is_started = false;
              if (!insert_item(new_client, fd_lookup))
                error("No room for additional clients");
              new_server.key = serverfd;
              new_server.fwdfd = i;
              new_server.is_started = false;
              if (!insert_item(new_server, fd_lookup))
                error("ERROR inserting client into the list");

              FD_SET (i, &active_fd_set);
              FD_SET (serverfd, &active_fd_set);
              // NEEDS WORK: How am I handling a failed CONNECT?
            }
            else if (strcmp(method, "GET") == 0) {
              printf("Get method received\n");
              *end_method = ' ';
              int status = check_cache(buf, cache, lru, &filled, &bytes_read, i);
              if (status == -2) {
                FD_CLR (i, &active_fd_set);
                continue;
              }
              else if (status != -1)
                status = send_to_server(buf, cache, lru, status, &bytes_read);
              
              if (status)
                n = write(i, buf, bytes_read);

              if (n < 0) 
                error("ERROR writing to socket");
              
              close(i); // QUESTION: Do we need to close i?
              FD_CLR (i, &active_fd_set);
            }
            else {
              // NEEDS WORK: Better error message or handle as valid
              error("Non-GET/CONNECT request... Is this unexpected?\n");
            }
          }
          else { // is https
            printf("Reading on socket %d\n", i);
            bzero(buf, BUFSIZE);
            n = read(cur_item->key, buf, BUFSIZE);
            printf("Read %d bytes\n", n);
            if (n < 0) {
              error("ERROR reading for tunnel");
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }
            else if (n == 0) {
              remove_item(cur_item, fd_lookup, &active_fd_set);
              continue;
            }

            if (cur_item->is_started) {
              printf("In tunnel: writing to fd %d\n", cur_item->fwdfd);
              n = write(cur_item->fwdfd, buf, n);
              if (n < 0) {
                error("ERROR writing for tunnel");
                remove_item(cur_item, fd_lookup, &active_fd_set);
                return 0;
              }
            }
            else {
              char sni[30];
              memset(sni, 0, 30);
              if (buf[0] == 22) {
                unsigned short totalLen = (buf[3] << 8) | buf[4];
                int lenSoFar = 0;
                if (buf[5] == 1) {
                  unsigned char sessIdLen = buf[43];
                  lenSoFar += sessIdLen + 43 + 1;
                  unsigned short cipherLen = ((unsigned char) buf[lenSoFar] << 8) | (unsigned char) buf[lenSoFar + 1];
                  lenSoFar += cipherLen + 2;
                  unsigned char compressLen = buf[lenSoFar];
                  lenSoFar += compressLen + 1;
                  unsigned short extensionLen = (unsigned char) buf[compressLen] << 8 | (unsigned char) buf[compressLen + 1];
                  lenSoFar += 2;
                  while (lenSoFar < totalLen) {
                    if (buf[lenSoFar] << 8 | buf[lenSoFar + 1] == 0){
                      if (buf[lenSoFar + 6] == 0) {
                        memcpy(sni, buf + lenSoFar + 9, buf[lenSoFar + 7] << 8 | buf[lenSoFar + 8]);
                        printf("SNI: %s\n", sni);
                        break;
                      }
                    }
                    lenSoFar = lenSoFar + (buf[lenSoFar + 3] << 8 | buf[lenSoFar + 4]) + 4;
                  }
                }
                n = write(cur_item->fwdfd, buf, n);
                if (n < 0) {
                  error("ERROR writing for tunnel");
                  remove_item(cur_item, fd_lookup, &active_fd_set);
                  return 0;
                }

                cur_item->is_started = true;
              }
            }
          }
        }
      }
    }
  }
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

int check_cache(char* buf, entry* cache, int* lru, int* filled, int* bytes_read, int clientfd) {

  /* String parsing gets hostname */
  char* hostname = strstr(buf, "Host: ") + 6;
  char* end_host = strstr(hostname, "\r\n");
  *end_host = 0;

  /* String parsing gets directory after hostname */
  char* first_line = strstr(buf, hostname);
  char* directory = strstr(first_line, "/");
  char* end_dir = strstr(first_line, " ");
  *end_dir = 0;
  
  char* key = malloc(strlen(hostname) + strlen(directory) + 1);
  strncpy(key, hostname, strlen(hostname));
  strncpy(key + strlen(hostname), directory, strlen(directory) + 1);
  // Return back to original
  *end_host = '\r';
  *end_dir = ' ';

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
      sprintf(age, "%d", time(NULL) - cache[key_exists].start_time);
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

void remove_item(item* cur_item, item* fd_lookup, fd_set* active_fd_p) {
  FD_CLR (cur_item->key, active_fd_p);
  FD_CLR (cur_item->fwdfd, active_fd_p);
  close(cur_item->key);
  close(cur_item->fwdfd);
  item* rem_item = find_item(cur_item->fwdfd, fd_lookup);
  cur_item->key = -1;
  rem_item->key = -1;
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
  return &NULL_ITEM;
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