#include "key_class.h"
#include <iostream>
#include <string>
#include <cstring>

#define KEY_BITS    4096

openssl_key::openssl_key()
{
    // create private/public key pair
    // init RSA context, so we can generate a key pair
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(key_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, KEY_BITS); // RSA KEY_BITS
    // variable that will hold both private and public keys
    EVP_PKEY *key = NULL;
    // generate key
    EVP_PKEY_keygen(key_ctx, &key);
    // free up key context
    EVP_PKEY_CTX_free(key_ctx); 
    
    // extract private key as string
    // create a place to dump the IO, in this case in memory
    BIO *private_BIO = BIO_new(BIO_s_mem());
    // dump key to IO
    PEM_write_bio_PrivateKey(private_BIO, key, NULL, NULL, 0, 0, NULL);
    // get buffer length
    int private_key_len = BIO_pending(private_BIO);
    // create char reference of private key length
    private_key_char = new uint8_t[private_key_len];
    // read the key from the buffer and put it in the char reference
    BIO_read(private_BIO, private_key_char, private_key_len);
    // write char array to BIO
    BIO *rsa_private_BIO = BIO_new_mem_buf(private_key_char, -1);
    // create a RSA object from private key char array
    RSA *rsa_private_key = NULL;
    PEM_read_bio_RSAPrivateKey(rsa_private_BIO, &rsa_private_key, NULL, NULL);
    // create private key
    private_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(private_key, rsa_private_key);
    
    // extract public key as string
    // create a place to dump the IO, in this case in memory
    BIO *public_BIO = BIO_new(BIO_s_mem());
    // dump key to IO
    PEM_write_bio_PUBKEY(public_BIO, key);
    // get buffer length
    public_key_len = BIO_pending(public_BIO);
    // create char reference of public key length
    public_key_char = new uint8_t[public_key_len];
    // read the key from the buffer and put it in the char reference
    BIO_read(public_BIO, public_key_char, public_key_len);
    // write char array to BIO
    BIO *rsa_public_BIO = BIO_new_mem_buf(public_key_char, -1);
    // create a RSA object from public key char array
    RSA *rsa_public_key = NULL;
    PEM_read_bio_RSA_PUBKEY(rsa_public_BIO, &rsa_public_key, NULL, NULL);
    // create public key
    public_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(public_key, rsa_public_key);    
}

openssl_key::~openssl_key()
{
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    delete [] public_key_char;
    delete [] private_key_char;
    delete [] ek;
    delete [] iv; 
}

int openssl_key::get_pub_key(uint8_t * public_key)
{
    memcpy(public_key, public_key_char, public_key_len);
    return 0;
}
int openssl_key::get_pub_key_len()
{
    return public_key_len;
}

void openssl_key::decrypt_data(uint8_t * encrypted_message, uint8_t* decrypted_message, int encrypted_message_len)
{

    // initialize decrypt context
    EVP_CIPHER_CTX *rsa_decrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsa_decrypt_ctx);
    // decrypt EK with private key, and get AES secretp
    EVP_OpenInit(rsa_decrypt_ctx, EVP_aes_256_cbc(), ek, ek_len, iv, private_key);

    // the length of the encrypted message
    int decrypted_message_len = 0;
    int decrypted_block_len = 0;
    // decrypt message with AES secret
    EVP_OpenUpdate(rsa_decrypt_ctx, decrypted_message, &decrypted_block_len, encrypted_message, encrypted_message_len);
    decrypted_message_len = decrypted_block_len;
    // finalize by decrypting padding
    EVP_OpenFinal(rsa_decrypt_ctx, decrypted_message + decrypted_block_len, &decrypted_block_len);
    decrypted_message_len += decrypted_block_len;
    
}

void openssl_key::set_ek(uint8_t *_ek, int _ek_len)
{
    ek_len = _ek_len;
    ek = new uint8_t[ek_len];
    memcpy(ek, _ek, ek_len);
}

void openssl_key::set_iv(uint8_t *_iv, int _iv_len)
{
    iv = new uint8_t[_iv_len];
    memcpy(iv, _iv, _iv_len);
}
