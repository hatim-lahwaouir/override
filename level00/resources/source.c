#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>



char welcome_message[105] = "[MATRIX] Bobby Newmark — unauthorized access detected.\n[BOBBY] You don't know what you've gotten into:"; 


void win() {
    system("/bin/sh");
}


void handle_client(int client_fd) {
    char buffer[72];


    write(client_fd, welcome_message, 105);
    

    read(client_fd, buffer, 256); 
    
    write(client_fd, "[BOBBY] Input received.\n", 24);
}


int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int optval = 1;

 
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = 37648; 
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 8);

    while (1) {
        do {
            client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        } while (client_fd < 0);

        if (fork() == 0) {
            close(server_fd); // Child doesn't need the listening socket
            
            dup2(client_fd, STDIN_FILENO);
            dup2(client_fd, STDOUT_FILENO);
            

            // Handle the client in an infinite loop
            while (1) {
                handle_client(client_fd);
            }
        }
        
        // --- Parent Process ---
        close(client_fd); // Parent doesn't need the connected socket
    }

    return 0;
}