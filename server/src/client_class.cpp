#include <iostream>
#include "client_class.h"
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
#include "client_class.h"
#include <iostream>

#define RECEIVE_MSG_MAX_LEN	4096

client::client(int _fd)
{
    is_handshake_completed = false;
    fd = _fd;
}

bool client::handshake()
{
    std::cout << "start handshake" << std::endl;
    
    // share public key with client
    int pub_key_len = client_key.get_pub_key_len();
    uint8_t* pub_key = new uint8_t[pub_key_len];
    client_key.get_pub_key(pub_key);
    int write_byte_count = write(fd, pub_key, pub_key_len); 
    delete [] pub_key;
    if(pub_key_len != write_byte_count)
    	return false;
    
    uint8_t *msg_buff = new uint8_t[RECEIVE_MSG_MAX_LEN];
    size_t msg_buff_len = 0;
    
    // get encrypted key from client
    msg_buff_len = read(fd, msg_buff, RECEIVE_MSG_MAX_LEN);
    if(msg_buff_len == 0)
    {
    	delete [] msg_buff;
    	return false;
    }
    client_key.set_ek(msg_buff,msg_buff_len);
    char a[] = "ok"; 
    write(fd, a, 1);     
    
    // get iv from client
    msg_buff_len = read(fd, msg_buff, EVP_MAX_IV_LENGTH);
    if(msg_buff_len == 0)
    {
    	delete [] msg_buff;
    	return false;
    }
    client_key.set_iv(msg_buff, msg_buff_len);
    
    is_handshake_completed = true; 
    
    delete [] msg_buff;
    
    return true;
}

void client::receive_msg()
{
    int msg_len = 0;
    uint8_t *msg_buff = new uint8_t[RECEIVE_MSG_MAX_LEN];
    
    std::cout << "wait for message" << std::endl;
    msg_len = read(fd, msg_buff, RECEIVE_MSG_MAX_LEN);
    
    if(msg_len <= 0)
    {
        delete [] msg_buff;
        return;
    }
    
    uint8_t *dec_msg = new uint8_t[msg_len + EVP_MAX_IV_LENGTH];
    client_key.decrypt_data(msg_buff, dec_msg, msg_len);
    std::cout << "message receved: " << dec_msg << std::endl;
    
    delete [] dec_msg;
    delete [] msg_buff;

}
