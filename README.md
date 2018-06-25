# LURK implementation with OpenSSL + NGINX

This project is based on the IETF drafts [LURK protocol version 1](https://tools.ietf.org/html/draft-mglt-lurk-lurk-00) and [LURK TLS1.2 extension](https://tools.ietf.org/html/draft-mglt-lurk-tls12-00).

The C implementation of LURK with OpenSSL + NGINX is quite interesting since both technologies are widely used and open sourced. However, OpenSSL implementation has to be modified in order to use certificates without their corresponding private keys. Hint: OpenSSL considers a pair <Certificate, Private Key> and both are accesed during the first steps of every TLS connection.

We managed to use LURK to sign ECDHE (ECDSA/RSA) parameters when establishing a TLS connection (concretely for the Server Key Exchange message). The current implementation still needs the certificate's private key to be stored in the LURK client and linked from the NGINX server configuration, although it will not be used to sign any information (only to initialize the OpenSSL library and select hash and ciphers during TLS handshake). Ideally, we need to modify the NGINX source code to avoid <PrivKey, Cert> vertification at first and then adapt the OpenSSL source code to avoid it as well.

TLS (ECDHE) handshake supports ECDSA and RSA signature algorithms and only named curves (same as OpenSSL).

TODO: (TLS) RSA handshake with LURK.
TODO: Implement missing functionalities (POO + PRF).
TODO: Identify key with key id and support for multiple keys/certificates (NGINX layer).

## Patch
The provided patch shows the changes for OpenSSL and NGINX source codes to support LURK.

## Configuration
*This implementation uses OpenSSL 1.1.0h*
### Client
The IP address and port of the LURK server are passed as environment variables, simple but enough for our prototype. Ideally, a LURK client would support different LURK servers depending on the requested SNI so this implementation must be improved, it must be coded at NGINX level.

### Server
The files containing the private keys are also passed as environment variables. LURK protocol uses **key id** to differenciate the requested key to sign or decrypt, but it hasn't been developed yet.

TODO: Password-protected keys (just add support through environment variables)

### LURK server
Configuration example
```bash
# Download, compile and install the latest version of OpenSSL (server-side OpenSSL is not modified)
# Compile server (Note: use -L and -I with the actual paths)
gcc -Wall -g -I/opt/openssl/include -L/opt/openssl/lib -o server server.c -lcrypto -lpthread
# Run server (with environment variables)
LURK_EC_KEY=/path/to/ec.key LURK_RSA_KEY=/path/to/rsa.key LURK_SERVER_PORT=5000 ./server
```

### LURK client
Configuration example
```bash
# Create LURK library
gcc -Wall -g -fPIC -shared -o liblurk.o -c lurk.c
ar -rc liblurk.a liblurk.o
# Now -llurk can be used with -L flag...
# Compile test_client (Note: use -L and -I with the actual paths)
gcc -L. -o client client.c -llurk
LURK_SERVER_ADDR=127.0.0.1 LURK_SERVER_PORT=5000 ./test

# Download and configure NGINX (Remember that OpenSSL will be compiled with NGINX).
# Important to apply the patch before compiling NGINX (which will also compile OpenSSL)
# Example https://www.vultr.com/docs/how-to-compile-nginx-from-source-on-ubuntu-16-04
```

## Test
Test examples
```bash
openssl s_client -cipher 'ECDHE-ECDSA-AES128-GCM-SHA256' -connect example.com:443
openssl s_client -cipher 'ECDHE-RSA-AES128-GCM-SHA256' -connect example.com:443
```

## Extra
### Support both ECDSA and RSA certificates
```bash
# Nginx site configuration
# ECDSA
ssl_certificate        /path/to/ecdsa.crt;
ssl_certificate_key    /path/to/ecdsa.key;

# RSA
ssl_certificate        /path/to/rsa.crt;
ssl_certificate_key    /path/to/rsa.key;
```

# License
This project is under a BSD 2-clause "Simplified" license.