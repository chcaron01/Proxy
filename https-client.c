// Ryan Megathlin

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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// Potential extras
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define BUFSIZE 10000000

void error(char *msg) {
  perror(msg);
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

int CertsMod(SSL* ssl_client, SSL* ssl_server)
{
    X509 *cert_client;
    X509 *cert_server;
    cert_client = SSL_get_peer_certificate(ssl_client); /* get the server's certificate */
    cert_server = SSL_get_peer_certificate(ssl_server); /* get the server's certificate */

    if ( cert_client != NULL && cert_server != NULL)
    {
      X509_NAME *subj_client = X509_get_subject_name(cert_client);
      X509_NAME *subj_server = X509_get_subject_name(cert_server);
      // There is supposed to be a for loop here... I'm confused by that. Apparently there can be
      // multiple common names?
      int pos_client = X509_NAME_get_index_by_NID(subj_client, NID_commonName, 0);
      int pos_server = X509_NAME_get_index_by_NID(subj_server, NID_commonName, 0);
      if (pos_client == -1 || pos_server == -1) {
        printf("Client: No common name...? Common name not modified\n");
      }
      else {
        X509_NAME_delete_entry(subj_client, pos_client);

        X509_NAME_ENTRY *e_server = X509_NAME_get_entry(subj_server, pos_server);

        int succ = X509_NAME_add_entry(subj_client, e_server, -1, -1);

        if (!succ) {
          printf("Set object for CN failed... Common name not modified\n");
        }
      }
      // End of hypothetical for loop

      // SAN Parsing starts here
      STACK_OF(X509_EXTENSION) *exts_client = cert_client->cert_info->extensions;
      STACK_OF(X509_EXTENSION) *exts_server = cert_server->cert_info->extensions;

      int loc_client = X509_get_ext_by_NID(cert_client, NID_subject_alt_name, -1);
      if (loc_client < 0) {
        error("Client: Getting index of Subject Alternative Name failed. SAN not modified");
        return -1;
      }
      int loc_server = X509_get_ext_by_NID(cert_server, NID_subject_alt_name, -1);
      if (loc_server < 0) {
        error("Server: Getting index of Subject Alternative Name failed. SAN not modified");
        return -1;
      }

      X509_EXTENSION *ext_client = X509v3_delete_ext(exts_client, loc_client);
      if (ext_client == NULL) {
        error("Client: Deleting Subject Alternative Name failed. SAN not modified");
      }
      X509_EXTENSION *ext_server = X509v3_get_ext(exts_server, loc_server);
      if (ext_server == NULL) {
        error("Server: Extracting Subject Alternative Name failed. SAN not modified");
      }

      X509v3_add_ext(&exts_client, ext_server, -1);
      // cert should now have the correct extension in it

      // SAN parsing ends here

      X509_free(cert_client);     /* free the malloc'ed certificate copy */
      X509_free(cert_server);
      return 1;
      // NEEDS WORK: Likely need more frees
    }
    else
      printf("Info: No client certificates configured.\n");


}

void PrintCert(SSL* ssl) {
  X509 *cert;
  char *line;
  STACK_OF(X509_EXTENSION) *exts;
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (cert != NULL)
  {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);       /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);       /* free the malloc'ed string */

    printf("Printing SAN Information\n");
        // SAN Parsing starts here
        exts = cert->cert_info->extensions;

        int loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
        // check that loc >= 0
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, loc);
        //IFNULL_FAIL(ex, "unable to extract extension from stack");
        // THOUGHT: If I get the ASN1_OBJECT, can that be inserted directly into the new cert?
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        //IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
          M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
        }

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
}

SSL* SSLConnect(int sockfd) {
  SSL_library_init(); //Possibly needs to be called outside function
  SSL_CTX* ctx = InitCTX();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);
  if (SSL_connect(ssl) == -1) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  else {
    return ssl;
  }
}

int main(int argc, char **argv) {
  //char* buf = malloc(BUFSIZE);

  char* hostname_google = "google.com";
  char* hostname_digicert = "digicert.com";
  int portno = 443;

  int googlefd = open_connection(hostname_google, portno);
  int digicertfd = open_connection(hostname_digicert, portno);
  SSL* ssl_google = SSLConnect(googlefd);
  SSL* ssl_digicert = SSLConnect(digicertfd);

  printf("Google Connected with %s encryption\n\n", SSL_get_cipher(ssl_google));
  printf("Digicert Connected with %s encryption\n\n", SSL_get_cipher(ssl_digicert));

  printf("********Google Certification********\n");
  PrintCert(ssl_google);
  printf("********Digicert Certification********\n");
  PrintCert(ssl_digicert);

  CertsMod(ssl_google, ssl_digicert);

  printf("********Google Certification********\n");
  PrintCert(ssl_google);
  printf("********Digicert Certification********\n");
  PrintCert(ssl_digicert);


  SSL_free(ssl_google);
  SSL_free(ssl_digicert);
  close(googlefd);
  close(digicertfd);
  //SSL_CTX_free(ctx); //NEEDS WORK: No access to ctx but is the backbone of the ssl
  return 0;

}





