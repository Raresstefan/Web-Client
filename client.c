#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "parson.h"
#include <sys/types.h>
#include "requests.h"
#include "helpers.h"

void add_new_user(int sockfd, char *user_name, char *password) {
    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);
    char **str = (char **) calloc(1, sizeof(char *));
    json_object_set_string(object, "username", user_name);
    json_object_set_string(object, "password", password);
    str[0] = json_serialize_to_string_pretty(value);
    // se creaza cerere de tip post catre server
    char *res = compute_post_request("34.241.4.235", "/api/v1/tema/auth/register", "application/json", str, 1, NULL, 0, NULL);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    char *token = strtok(received, " ");
    token = strtok(NULL, " ");
    // se verifica daca operatia s-a putut executa cu succes
    if (strcmp(token, "201") == 0) {
        printf("Utilizator inregistrat cu succes!\n");
    } else {
        // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
        printf("Inregistrarea a esuat. Va rugam incercati alt username\n");
    }
    json_value_free(value);
    json_free_serialized_string(str[0]);
    free(str);
    free(res);
    free(received);
    close(sockfd);
}

char *login(int sockfd, char *user_name, char *password) {
    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);
    char **str = (char **) calloc(1, sizeof(char *));
    json_object_set_string(object, "username", user_name);
    json_object_set_string(object, "password", password);
    printf("%s", user_name);
    printf("%s", password);
    str[0] = json_serialize_to_string_pretty(value);
    // se creaza cerere de tip post catre server
    char *res = compute_post_request("34.241.4.235", "/api/v1/tema/auth/login", "application/json", str, 1, NULL, 0, NULL);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Eroare la login\n");
        char *basic_response = basic_extract_json_response(received);
        if (basic_response != NULL) {
            printf("Raspunsul de la server: %s \n", basic_response);
        } else {
            printf("Raspunsul de la server: %s \n", received);
        }
        free(res);
        free(received);
        json_free_serialized_string(str[0]);
        free(str);
        json_value_free(value);
        close(sockfd);
        return NULL;
    }
    printf("Logarea s-a executat cu succes\n");

    char *copy_cookie;
    // se extrage cookie-ul primit de la server
    copy_cookie = strstr(received, "Set-Cookie: ");
    copy_cookie = strtok(copy_cookie, " ");
    copy_cookie = strtok(NULL, ";");
    char *cookie = strdup(copy_cookie);
    json_free_serialized_string(str[0]);
    json_value_free(value);
    free(received);
    free(res);
    close(sockfd);
    // se returneaza cookie-ul primit de la server
    return cookie;
}

int logout(int sockfd, char *cookie) {
    // se verifica daca utilizatorul este logat
    if (cookie == NULL) {
        printf("Nu sunteti logat\n");
        return 0;
    }
    // se creaza cerere de tip get catre server
    char *res = compute_get_request("34.241.4.235", "/api/v1/tema/auth/logout", NULL, cookie, 1, NULL);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Nu s-a reusit delogarea\n");
        free(received);
        free(res);
        return 0;
    }
    free(received);
    free(res);
    printf("Delogarea s-a executat cu succes\n");
    return 1;
}

void enter_library(int sockfd, char **cookie, char **jwt_token) {
    // se verifica daca utilizatorul este logat
    if (*cookie == NULL) {
        printf("Nu sunteti logat\n");
        return;
    }
    // se verifica daca utilizatorul a primit autorizatie pentru a accesa biblioteca
    if (*jwt_token != NULL) {
        printf("Aveti deja autorizatie\n");
    }
    // se creaza cerere de tip get catre server
    char *res = compute_get_request("34.241.4.235", "/api/v1/tema/library/access", NULL, *cookie, 1, NULL);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    printf("%s\n", received);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Accesul la biblioteca nu a reusit\n");
        free(received);
        free(res);
        close(sockfd);
        return;
    }
    // se extrage token-ul din raspunsul primit de la server
    char *token = basic_extract_json_response(received);
    token = strstr(token, ":");
    *jwt_token = (char *) calloc(strlen(token + 2) + 1, sizeof(char));
    strcpy(*jwt_token, token + 2);
    (*jwt_token)[strlen(*jwt_token) - 2] = '\0';
    free(res);
    free(received);
    close(sockfd);
}

void view_books(int sockfd, char **cookie, char **jwt_token) {
    // se verifica daca utilizatorul este logat
    if (*cookie == NULL) {
        printf("Nu sunteti logat.\n");
        return;
    }
    // se verifica daca utilizatorul a primit autorizatie pentru a accesa biblioteca
    if (*jwt_token == NULL) {
        printf("Nu aveti acces la biblioteca.\n");
        return;
    }
    // se creaza cerere de tip get catre server
    char *res = compute_get_request("34.241.4.235", "/api/v1/tema/library/books", NULL, *cookie, 1, *jwt_token);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Vizualizarea cartilor nu s-a putut realiza.\n");
        free(received);
        free(res);
        return;
    }
    char *books = basic_extract_json_response(received);
    if (books == NULL) {
        // in cazul in care nu exista nicio carte in biblioteca
        // utilizatorului se intoarce o lista goala
        printf("[]\n");
        printf("Nu dispuneti de nicio carte.\n");
        free(received);
        free(res);
        return;
    } else {
        printf("Aveti urmatoarele carti: \n");
        printf("%s\n", books);
    }
    free(received);
    free(res);
}

void add_book(int sockfd, char **cookie, char **jwt_token,
char *title, char *author, char *genre, char *publisher, char *page_count) {
    // se verifica daca utilizatorul este logat
    if (*cookie == NULL) {
        printf("Nu sunteti logat.\n");
        return;
    }
    // se verifica daca utilizatorul a primit autorizatie pentru a accesa biblioteca
    if (*jwt_token == NULL) {
        printf("Nu aveti acces la biblioteca.\n");
        return;
    }
    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);
    json_object_set_string(object, "title", title);
    json_object_set_string(object, "author", author);
    json_object_set_string(object, "genre", genre);
    json_object_set_string(object, "publisher", publisher);
    json_object_set_string(object, "page_count", page_count);
    char **str = (char **) calloc(1, sizeof(char *));
    str[0] = json_serialize_to_string_pretty(value);
    // se creaza cerere de tip post catre server
    char *res = compute_post_request("34.241.4.235", "/api/v1/tema/library/books", "application/json", str, 1, NULL, 0, *jwt_token);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Cartea nu s-a putut adauga");
        json_free_serialized_string(str[0]);
        free(str);
        free(res);
        free(received);
        close(sockfd);
        return;
    }
    printf("Cartea a fost adauagata.\n");
    json_free_serialized_string(str[0]);
    free(str);
    free(res);
    free(received);
    close(sockfd);
}

void get_book(int sockfd, int id, char **cookie, char **jwt_token) {
    // se verifica daca utilizatorul este logat
    if (*cookie == NULL) {
        printf("Nu sunteti logat.\n");
        return;
    }
    // se verifica daca utilizatorul a primit autorizatie pentru a accesa biblioteca
    if (*jwt_token == NULL) {
        printf("Nu aveti acces la biblioteca.\n");
        return;
    }
    char path[100];
    strcpy(path, "/api/v1/tema/library/books/");
    char id_str[50];
    sprintf(id_str, "%d", id);
    // se adauga id-ul cartii in calea de acces
    strcat(path, id_str);
    // se creaza cerere de tip post catre server
    char *res = compute_get_request("34.241.4.235", path, NULL, *cookie, 1, *jwt_token);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Informatiile despre cartea ceruta nu s-au putut transmite.\n");
        free(res);
        free(received);
        return;
    }
    // se afiseaza informatiile cartii
    printf("Informatiile despre cartea cu id-ul: %d sunt urmatoarele: \n", id);
    char *information = basic_extract_json_response(received);
    printf("%s\n", information);
    free(res);
    free(received);
}

void delete_book(int sockfd, int id, char **cookie, char **jwt_token) {
    // se verifica daca utilizatorul este logat
    if (*cookie == NULL) {
        printf("Nu sunteti logat.\n");
        return;
    }
    // se verifica daca utilizatorul a primit autorizatie pentru a accesa biblioteca
    if (*jwt_token == NULL) {
        printf("Nu aveti acces la biblioteca.\n");
        return;
    }
    char path[100];
    strcpy(path, "/api/v1/tema/library/books/");
    char id_str[50];
    sprintf(id_str, "%d", id);
    // se adauga id-ul cartii in calea de acces
    strcat(path, id_str);
    // se creaza cerere de tip delete catre server
    char *res = compute_delete_request("34.241.4.235", path, *cookie, 1, *jwt_token);
    // se trimite cererea catre server
    send_to_server(sockfd, res);
    // se primeste raspunsul de la server
    char *received = receive_from_server(sockfd);
    // se verifica daca operatia s-a putut executa cu succes
    char *is_ok = strstr(received, "OK");
    // in cazul in care operatia a esuat se afiseaza un mesaj de eroare
    if (is_ok == NULL) {
        perror("Cartea nu a putut fi eliminata.\n");
        free(res);
        free(received);
        return;
    }
    printf("Cartea cu id-ul: %d a fost stearsa.\n", id);
    free(res);
    free(received);
}

int main() {
    int sockfd;
    char command[700];
    int id;
    char *cookie = NULL;
    char *jwt_token = NULL;
    while(1) {
        fgets(command, 700, stdin);
        command[strlen(command) - 1] = '\0';
        setvbuf(stdin, NULL, _IONBF, 0);
        if (strcmp(command, "exit") == 0) {
            break;
        }
        if (strcmp(command, "register") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            // se verifica daca utilizatorul este deja logat intr-un cont
            if (cookie != NULL) {
                printf("Sunteti deja logat.\n");
                close(sockfd);
                continue;
            }
            char *user_name = (char *) calloc(300, sizeof(char));
            char *password = (char *) calloc(300, sizeof(char));
            printf("username=");
            // se citeste username-ul
            do {
                fgets(user_name, 300, stdin);
                user_name[strlen(user_name) - 1] = '\0';
                if (strlen(user_name) == 0) {
                    printf("Nu ati introdus un Username\n");
                }
            } while(strlen(user_name) == 0);
            printf("password=");
            // se citeste parola
            do {
                fgets(password, 300, stdin);
                password[strlen(password) - 1] = '\0';
                if (strlen(password) == 0) {
                    printf("Nu ati introdus o parola\n");
                }
            } while(strlen(password) == 0);
            add_new_user(sockfd, user_name, password);
            free(user_name);
            free(password);
            close(sockfd);
        } else if (strcmp(command, "login") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            // se verifica daca utilizatorul este deja logat intr-un cont
            if (cookie != NULL) {
                printf("Sunteti deja logat.\n");
                close(sockfd);
                continue;
            }
            char *user_name = (char *) calloc(300, sizeof(char));
            char *password = (char *) calloc(300, sizeof(char));
            printf("username=");
            // se citeste username-ul
            do {
                fgets(user_name, 300, stdin);
                user_name[strlen(user_name) - 1] = '\0';
                if (strlen(user_name) == 0) {
                    printf("Nu ati introdus un Username\n");
                }
            } while(strlen(user_name) == 0);
            printf("password=");
            // se citeste parola
            do {
                fgets(password, 300, stdin);
                password[strlen(password) - 1] = '\0';
                if (strlen(password) == 0) {
                    printf("Nu ati introdus o parola\n");
                }
            } while(strlen(password) == 0);
            cookie = login(sockfd, user_name, password);
            if (cookie == NULL) {
                printf("Nu s-a intors niciun cookie\n");
            }
            close(sockfd);
            free(user_name);
            free(password);
        } else if(strcmp(command, "logout") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            int res = logout(sockfd, cookie);
            if (res != 1) {
                close(sockfd);
                continue;
            }
            cookie = NULL;
            jwt_token = NULL;
            close(sockfd);
        } 
        else if (strcmp(command, "enter_library") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            // se verifica daca utilizatorul are deja acces la biblioteca
            if (jwt_token != NULL) {
                printf("Aveti deja acces la biblioteca\n");
                close(sockfd);
                continue;
            }
            enter_library(sockfd, &cookie, &jwt_token);
            if (jwt_token != NULL) {
                printf("Accesult la biblioteca s-a realizat cu succes\n");
            } else {
                perror("Accesul la biblioteca nu s-a realizat\n");
                close(sockfd);
                continue;
            }
        } else if (strcmp(command, "get_books") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            view_books(sockfd, &cookie, &jwt_token);
            close(sockfd);
        } else if (strcmp(command, "get_book") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            printf("id=");
            // se citeste id-ul cartii
            scanf("%d", &id);
            get_book(sockfd, id, &cookie, &jwt_token);
            close(sockfd);
        } else if (strcmp(command, "add_book") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            char *title = (char *) calloc(300, sizeof(char));
            char *author = (char *) calloc(300, sizeof(char));
            char *genre = (char *) calloc(300, sizeof(char));
            char *publisher = (char *) calloc(300, sizeof(char));
            char *page_count = (char *) calloc(300, sizeof(char));
            printf("title=");
            // se citeste titlul cartii
            fgets(title, 300, stdin);
            title[strlen(title) - 1] = '\0';
            printf("author=");
            // se citeste autorul cartii
            fgets(author, 300, stdin);
            author[strlen(author) - 1] = '\0';
            printf("genre=");
            // se citeste genul cartii
            fgets(genre, 300, stdin);
            genre[strlen(genre) - 1] = '\0';
            printf("publisher=");
            // se citeste editura cartii
            fgets(publisher, 300, stdin);
            publisher[strlen(publisher) - 1] = '\0';
            printf("page_count=");
            // se citeste numarul de pagini al cartii cartii
            fgets(page_count, 300, stdin);
            page_count[strlen(page_count) - 1] = '\0';
            add_book(sockfd, &cookie, &jwt_token,
            title, author, genre, publisher, page_count);
            free(title);
            free(author);
            free(publisher);
            free(genre);
            free(page_count);
        } else if (strcmp(command, "delete_book") == 0) {
            // se creaza conexiunea cu server-ul
            sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
            printf("id=");
            // se citeste id-ul cartii
            scanf("%d", &id);
            delete_book(sockfd, id, &cookie, &jwt_token);
            close(sockfd);
        }
    }
    return 0;
}
