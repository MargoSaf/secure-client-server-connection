#ifndef KEY_CLASS_H
#define KEY_CLASS_H

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

class openssl_key
{
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    uint8_t *public_key_char;
    uint8_t *private_key_char;
    int public_key_len;
    uint8_t *ek;
    int ek_len;
    uint8_t *iv; 
    
public:
    openssl_key();
    ~openssl_key();
    int get_pub_key(uint8_t * public_key);
    int get_pub_key_len();
    void decrypt_data(uint8_t * encrypted_message, uint8_t* decrypted_message, int len);
    void set_ek(uint8_t *_ek, int _ek_len);
    void set_iv(uint8_t *_iv, int _iv_len);
};
 
#endif

