#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 
#include "src/client_class.h"
#include <iostream>

int main(int argc, char *argv[])
{
    int listen_fd = 0, conn_fd = 0;
    struct sockaddr_in serv_addr; 

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000); 

    bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

    listen(listen_fd, 10); 
   
    conn_fd = accept(listen_fd, (struct sockaddr*)NULL, NULL); 
    std::cout << "connection accepted " <<std::endl;
    client client_(conn_fd);
    
    if(client_.handshake())
    {
        std::cout << "handshake completed"<<std::endl;
        client_.receive_msg();
        close(conn_fd);
    }

}
