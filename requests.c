#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

char *compute_get_request(char *host, char *url, char *query_params,
                            char *cookies, int cookies_count, char *jwt)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // se scrie tipul de cerere GET, URL si tipul protocolului
    if (query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // se aduaga header-ul de Host
    strcat(message, "Host:");
    compute_message(message, host);

    // se adauga header-ul de Cookie daca este necesar
    if (cookies != NULL) {
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }

    // se adauga header-ul de Autorizatie, daca este necesar
    if (jwt != NULL) {
        sprintf(line, "Authorization: Bearer %s", jwt);
        compute_message(message, line);
    }

    // se audaga o linie noua la final
    compute_message(message, "");
    free(line);
    return message;
}

char *compute_post_request(char *host, char *url, char* content_type, char **body_data,
                            int body_data_fields_count, char *cookies, int cookies_count, char*jwt)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *body_data_buffer = calloc(LINELEN, sizeof(char));

    // se scrie tipul de cerere, URL si tipul protocolului
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    // se adauca header-ul de HOST
    strcat(message, "Host:");
    compute_message(message, host);

    // se audaga header-ul de Content-Type
    strcat(message, "Content-Type:");
    compute_message(message, content_type);

    for (int i = 0; i < body_data_fields_count; ++i) {
        strcat(body_data_buffer, body_data[i]);
        if (i != body_data_fields_count - 1) {
            strcat(body_data_buffer, "&");
        }
    }

    char* length = (char *) malloc (10 * sizeof(char));
    sprintf(length, "%ld", strlen(body_data_buffer));

    // se adauga header-ul de Content-Length
    strcat(message, "Content-Length:");
    compute_message(message, length);

    free(length);

    // Se aduga header-ul de Cookie, daca este necesar 
    if (cookies != NULL) {
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }

    // se adauga header-ul de Autorizatie, daca este necesar
    if (jwt != NULL) {
        sprintf(line, "Authorization: Bearer %s", jwt);
        compute_message(message, line);
    }

    // se adauga o linie noua la finalul header-ului
    strcat(message, "\r\n");

    // se adauga un payload in sectiunea de DATE
    memset(line, 0, LINELEN);
    compute_message(message, body_data_buffer);

    free(line);
    free(body_data_buffer);
    return message;
}

char *compute_delete_request(char *host, char *url, char *cookies, int cookies_count, char *jwt)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    
    // se scrie tipul de cerere, URL si tipul protocoului folosit
    sprintf(line, "DELETE %s HTTP/1.1", url);
    compute_message(message, line);

    // memset(line, 0, LINELEN);

    // se aduaga header-ul de HOST
    strcat(message, "Host:");
    compute_message(message, host);

    // se adauga header-ul de Cookie, daca este nevoie 
    if (cookies != NULL) {
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }

    // se adauga header-ul de AUtorizatie, daca este nevoie
    if (jwt != NULL) {
        sprintf(line, "Authorization: Bearer %s", jwt);
        compute_message(message, line);
    }
    
    compute_message(message, "");
    free(line);

    return message;
}
