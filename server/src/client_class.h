#ifndef CLIENT_CLASS_H
#define CLIENT_CLASS_H

#include "key_class.h"

class client
{
    int fd;
    openssl_key client_key;
    bool is_handshake_completed;
public:
    client(int _fd = -1);
    bool handshake();
    void receive_msg();
};

#endif

