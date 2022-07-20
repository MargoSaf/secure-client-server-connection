# secure-client-server-connection
An application typically uses openssl to encrypt and decrypt a message using a public/private key.

The application includes the following parts to transfer secure data: 
1) Creates connection between client and server
2) Server generates key pair for the client
3) Handshake between client and serever
4) Client sends the meesage encrypted with AES key 
5) Server opens the message with AES key
