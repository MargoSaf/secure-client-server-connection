#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <iostream>

#include <openssl/evp.h>
#include <openssl/pem.h>

#define PUB_KEY_LEN		800 // As we have fixed the key length on server side we can fix the public key size on client side
#define RECV_BUFF_MAX_LEN	800
 
int main(int argc, char *argv[])
{
    int sock_fd = 0, recv_buff_len = 0;
    char recv_buff[RECV_BUFF_MAX_LEN];
    struct sockaddr_in serv_addr; 
    
    memset(recv_buff, '0',sizeof(recv_buff));
    memset(&serv_addr, '0', sizeof(serv_addr)); 
        
    if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        std::cout << "Error : Could not create socket " << std::endl;
        return 1;
    } 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000); 
    
    if( connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cout << "Error : Connect Failed" << std::endl;
        return 1;
    } 

    std::cout << "wait for get public key" << std::endl;
    recv_buff_len = read(sock_fd, recv_buff, PUB_KEY_LEN);
    if(recv_buff_len != PUB_KEY_LEN)
    {
        std::cout << "Error : Failed to get public key" << std::endl;
        return 1;
    }

    // write char array to BIO
    BIO *rsa_public_BIO = BIO_new_mem_buf(recv_buff, -1);
    // create a RSA object from public key char array
    RSA *rsa_public_key = NULL;
    PEM_read_bio_RSA_PUBKEY(rsa_public_BIO, &rsa_public_key, NULL, NULL);
    // create public key
    EVP_PKEY *public_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(public_key, rsa_public_key);
    // initialize encrypt context
    EVP_CIPHER_CTX *rsa_encrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsa_encrypt_ctx);
    // variables for where the encrypted secret, length, and IV reside
    uint8_t *ek = (uint8_t *) malloc(EVP_PKEY_size(public_key));
    int ekLen = 0;
    uint8_t *iv = (uint8_t *) malloc(EVP_MAX_IV_LENGTH);
    // generate AES secret, and encrypt it with public key
    EVP_SealInit(rsa_encrypt_ctx, EVP_aes_256_cbc(), &ek, &ekLen, iv, &public_key, 1);

    std::cout << "start handshake" << std::endl;
    write(sock_fd, ek, ekLen);  
    recv_buff_len = read(sock_fd, recv_buff, 2);
    if(recv_buff_len <= 0)
    {
        std::cout << "Error : Handshake Failed" << std::endl;
        return 1;
    } 
    write(sock_fd, iv, EVP_MAX_IV_LENGTH); 
    
    // encrypt a message with AES secret
    uint8_t message_char[] = "Openssl learning, hello";;
    // length of message
    int message_len = sizeof(message_char);
    // create char reference for where the encrypted message will reside
    uint8_t encrypted_message[message_len + EVP_MAX_IV_LENGTH];
    // the length of the encrypted message
    int encrypted_message_len = 0;
    int encrypted_block_len = 0;
    // encrypt message with AES secret
    EVP_SealUpdate(rsa_encrypt_ctx, encrypted_message, &encrypted_block_len, message_char, message_len);
    encrypted_message_len = encrypted_block_len;
    // finalize by encrypting the padding
    EVP_SealFinal(rsa_encrypt_ctx, encrypted_message + encrypted_block_len, &encrypted_block_len);
    encrypted_message_len += encrypted_block_len;

    std::cout << "send message" << std::endl;
    write(sock_fd, encrypted_message, encrypted_message_len); 

    return 0;
}
