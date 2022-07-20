# secure-client-server-connection
In application, the common usage of openssl to encrypt and decrypt a message with public/private key.

The application did the following parts to transfer secure data: 
1) Creates connection between client and server
2) Server generates key pair for the client
3) Handshake between client and serever
4) Client sends the meesage encrypted with AES key 
5) Server opens the message with AES key
