#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#define SIZE 1024
#define BACKLOG 128  // Passed to listen()
#define PORT 80
pthread_mutex_t mutex;

const char httpResponse[8000] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\nok";

void *thread_main(void *arg)
{
    int clientSocket = (int)*((int *)(arg));
    pthread_mutex_unlock(&mutex);
    int res;
    send(clientSocket, httpResponse, sizeof(httpResponse), 0);
    res = shutdown(clientSocket, SHUT_RDWR);
    if(res != 0)
        printf("shutdown failed!");
    res = close(clientSocket);
    if(res != 0)
        printf("close failed!");
}

int main(void)
{
    if (pthread_mutex_init(&mutex,NULL) != 0) {
        perror("mutex init error");
        exit(-1);
    }

    // Socket setup: creates an endpoint for communication, returns a descriptor
    int serverSocket = socket(
        AF_INET,      // Domain: specifies protocol family
        SOCK_STREAM,  // Type: specifies communication semantics
        0             // Protocol: 0 because there is a single protocol for the specified family
    );

    // Construct local address structure
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to local address
    // bind() assigns the address specified by serverAddress to the socket
    // referred to by the file descriptor serverSocket.
    bind(
        serverSocket,                         // file descriptor referring to a socket
        (struct sockaddr *) &serverAddress,   // Address to be assigned to the socket
        sizeof(serverAddress)                 // Size (bytes) of the address structure
    );

    // Mark socket to listen for incoming connections
    int listening = listen(serverSocket, BACKLOG);
    if (listening < 0) {
        printf("Error: The server is not listening.\n");
        return 1;
    }

    // Wait for a connection, create a connected socket if a connection is pending
    printf("Server started!\n");
    while(1) {
        int clientSocket;
        int clientSocket_temp;
        pthread_t t_id;
        struct sockaddr_in addrClient;
        socklen_t len = sizeof(struct sockaddr_in);
        clientSocket = accept(serverSocket, (struct sockaddr *)&addrClient, &len);

        pthread_mutex_lock(&mutex);
        clientSocket_temp = clientSocket;
        printf("Received request from %s:%d\n", inet_ntoa(addrClient.sin_addr), ntohs(addrClient.sin_port));

        int err = pthread_create(&t_id, NULL, thread_main, (void *)&clientSocket_temp);
        if(err != 0)
        {
            printf("pthread_create() error: %d\n", err);
            close(clientSocket_temp);
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    return 0;
}
