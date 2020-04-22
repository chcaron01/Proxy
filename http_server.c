// To compile on mac, do: gcc -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o server -g http_server.c -lssl -lcrypto

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

EVP_PKEY * generate_key();
X509 * generate_x509(EVP_PKEY * pkey, char * CN);

void error(char *msg) {
  perror(msg);
}

EVP_PKEY * generate_key() {
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }
    
    /* Generate the RSA key and assign it to pkey. */
    FILE *fp = fopen("./root-cert/EMEN.key", "r");
    RSA * rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, "elephantmen");
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* The key has been generated, return it. */
    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 * generate_x509(EVP_PKEY * pkey, char * CN) {
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
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
    X509_NAME * name = X509_get_subject_name(x509);
    
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) CN, -1, -1, 0);
    
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    
    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, pkey, EVP_sha1()))
    {
        printf("here\n");
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
}

void cleanup_openssl()
{
    EVP_cleanup();
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

void configure_context(SSL_CTX *ctx, X509 * cert, EVP_PKEY *pkey)
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

// From https-client.c

SSL_CTX* InitCTX(void)
{
    SSL_METHOD* method;
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

int open_connection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        error("ERROR getting hostname");
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        error("ERROR connecting to server");
        abort();
    }
    return sd;
}

X509 * CertsMod(SSL* ssl_client, SSL* ssl_server)
{
    X509 *cert_client;
    X509 *cert_server;
    cert_client = SSL_get_certificate(ssl_client);
    // cert_client = SSL_get_certificate(ssl_client); /* get the client's certificate */
    cert_server = SSL_get_peer_certificate(ssl_server); /* get the server's certificate */

    if ( cert_client != NULL && cert_server != NULL)
    {
      X509_NAME *subj_client = X509_get_subject_name(cert_client);
      X509_NAME *subj_server = X509_get_subject_name(cert_server);

      int pos_client = X509_NAME_get_index_by_NID(subj_client, NID_commonName, 0);
      int pos_server = X509_NAME_get_index_by_NID(subj_server, NID_commonName, 0);
      if (pos_server == -1) {
        printf("ERROR: Server does not have common name\n");
        return -1;
      }
      X509_NAME_delete_entry(subj_client, pos_client);
      X509_NAME_ENTRY *e_server = X509_NAME_get_entry(subj_server, pos_server);
      int succ = X509_NAME_add_entry(subj_client, e_server, -1, -1);

      if (!succ) {
        printf("Set object for CN failed... Common name not modified\n");
        return -1;
      }

      X509_set_subject_name(cert_client, subj_client);

      // SAN Parsing starts here
      int loc_server = X509_get_ext_by_NID(cert_server, NID_subject_alt_name, -1);
      if (loc_server < 0) {
        error("Server: Getting index of Subject Alternative Name failed. SAN not modified");
        return -1;
      }

      X509_EXTENSION *ext_server = X509_get_ext(cert_server, loc_server);
      if (ext_server == NULL) {
        error("Server: Extracting Subject Alternative Name failed. SAN not modified");
      }

      X509_add_ext(cert_client, ext_server, -1);
      // cert should now have the correct extension in it
      return cert_client;

      // SAN parsing ends here

      //X509_free(cert_client);     /* free the malloc'ed certificate copy */
      X509_free(cert_server);
      // NEEDS WORK: Likely need more frees
    }
    else {
      printf("Info: No certificates found\n");
      return -1;
    }
}

void PrintCert(SSL* ssl) {
  X509 *cert;
  char *line;
  STACK_OF(X509_EXTENSION) *exts;
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (cert == NULL) {
    cert = SSL_get_certificate(ssl);
  }
  if (cert != NULL)
  {
    printf("Certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);       /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);       /* free the malloc'ed string */

    printf("Printing SAN Information\n");
        // SAN Parsing starts here

        int loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
        // check that loc >= 0
        X509_EXTENSION *ex = X509_get_ext(cert, loc);
        //IFNULL_FAIL(ex, "unable to extract extension from stack");
        // THOUGHT: If I get the ASN1_OBJECT, can that be inserted directly into the new cert?
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        //IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
        // if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
        //     ASN1_OCTET_STRING* octet_str = X509_EXTENSION_get_data(ex);
        //     M_ASN1_OCTET_STRING_print(ext_bio, octet_str);
        // }

        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
          bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
          bptr->data[lastchar] = (char) 0;
        }

        BIO_free(ext_bio);

        unsigned nid = OBJ_obj2nid(obj);
        if (nid == NID_undef) {
          printf("If is true\n");
          // no lookup found for the provided OID so nid came back as undefined.
          int EXTNAME_LEN = 8000;
          char extname[EXTNAME_LEN];
          OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
          printf("\n\nextension name is %s\n", extname);
        } else {
          // the OID translated to a NID which implies that the OID has a known sn/ln
          const char *c_ext_name = OBJ_nid2ln(nid);
          //IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
          printf("extension name is %s\n", c_ext_name);
        }

        printf("extension length is %lu\n", bptr->length);
        printf("extension value is %s\n", bptr->data);
  }
  else {
    printf("Printing cert failed\n");
  }
}

SSL* SSLConnect(int sockfd, const char* SNI) {
  SSL_library_init(); //Possibly needs to be called outside function
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

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    char* hostname_digicert = "digicert.com";
    int portno = 443;
    int digicertfd = open_connection(hostname_digicert, portno);
    SSL* ssl_digicert = SSLConnect(digicertfd, hostname_digicert);
    printf("********Digicert Certification********\n");
    PrintCert(ssl_digicert);

    init_openssl();
    ctx = create_context();

    //EVP_PKEY * pkey = generate_key();
    //X509 * cert = generate_x509(pkey, "google.com");
    configure_context(ctx, NULL, NULL);

    SSL *ssl = SSL_new(ctx);
    X509* new_cert = CertsMod(ssl, ssl_digicert);
    if (!SSL_use_certificate(ssl, new_cert)) {
      printf("Modified cert failed to insert into SSL\n");
      exit(1);
    }
    printf("********Proxy Certification********\n");
    PrintCert(ssl);

    sock = create_socket(9000);
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
         (const void *)&optval , sizeof(int));

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL_set_fd(ssl, client);

        char ignore[100000];
        int n = read(client, ignore, 100000);
        if (n < 0) {
          printf("ERROR reading from client");
          return -1;
        }

        // Report to the client that connection was successful
        char* okay_response = "HTTP/1.1 200 OK\r\n\r\n";

        n = write(client, okay_response, strlen(okay_response));
        if (n < 0) {
          printf("ERROR writing to client");
          return -1;
        }

        if (SSL_accept(ssl) <= 0) {
            printf("IT FAILED\n");
            ERR_print_errors_fp(stderr);
        }
        else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}