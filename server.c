/*
 * Copyright (C) 2018 Orange
 * 
 * This software is distributed under the terms and conditions of the '2-Clause BSD License'
 * license which can be found in the file 'LICENSE' in this package distribution 
 * or at 'https://opensource.org/licenses/BSD-2-Clause'. 
 */

/*
 * LURK protocol implementation as defined in draft-mglt-lurk-lurk-00,
 * This file contains a simple LURK server over UDP.
 */

#include <stdio.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "lurk.h"

#define BUFFER_MAX_LENGTH 1500 // TODO: How much?

int main(void) {
  // Get server port from environment variable
  const char *server_port_str = getenv("LURK_SERVER_PORT");
  if (server_port_str == NULL) {
    printf("Error: LURK server port to be listened not specified. Use env 'LURK_SERVER_PORT'.\n");
    return 1;
  }
  short server_port = atoi(server_port_str);

  // Create UDP socket
  int server_socket = socket(PF_INET, SOCK_DGRAM, 0);

  // Configure settings in address struct
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  memset(server_addr.sin_zero, '\0', sizeof server_addr.sin_zero);  

  // Bind socket with address struct
  if (bind(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
    printf("Failed to bind socket\n");
    return 1;
  }

  // Client will be stored in server_storage (address and port) to know where to send the response to
  struct sockaddr_storage server_storage;
  socklen_t addr_size = sizeof server_storage;

  // Initialize ECDHE and RSA (see https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/apps/ec.c)
  // Get ec and rsa private keys from environment variables
  const char *ec_keyfile = getenv("LURK_EC_KEY");
  const char *rsa_keyfile = getenv("LURK_RSA_KEY");
  if ((ec_keyfile == NULL) || (rsa_keyfile == NULL)) {
    printf("Error: LURK server address or port not defined. Use env 'LURK_EC_KEY' and 'LURK_RSA_KEY'.\n");
    return 1;
  }
  // TODO: Create environment variables for both passwords (if any): 'LURK_EC_KEY_PASSWORD' and 'LURK_RSA_KEY_PASSWORD'

  // Read ECDSA
  BIO *in = BIO_new(BIO_s_file());
  if (!BIO_read_filename(in, ec_keyfile)) {
    printf("Error reading ECDSA private key file\n");
  }
  EVP_PKEY *ec_pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL); // PEM_read_bio_ECPrivateKey(in, NULL, NULL, (void *)password);
  if (!ec_pkey) {
    printf("Error getting ECDSA private key\n");
    return 1;
  }
  
  // Read RSA
  if (!BIO_read_filename(in, rsa_keyfile)) {
    printf("Error reading RSA private key file\n");
  }
  EVP_PKEY *rsa_pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL); // PEM_read_bio_RSAPrivateKey(in, NULL, NULL, (void *)password);
  if (!rsa_pkey) {
    printf("Error getting RSA private key\n");
    return 1;
  }
  BIO_free(in);
  
  // Create buffer to store
  unsigned char buffer[BUFFER_MAX_LENGTH];

  for (;;) {
    // Receive any incoming UDP datagram (to our socket <address, port>)
    int recv_bytes = recvfrom(server_socket, buffer, BUFFER_MAX_LENGTH, 0, (struct sockaddr *)&server_storage, &addr_size);
    if (recv_bytes < LURK_HEADER_LENGTH) {
      continue;
    }
    
    // Parse response as lurk_pdu
    struct lurk_pdu *request = (struct lurk_pdu *)buffer;

    // Create response
    struct lurk_pdu response;
    uint32_t total_length; // TODO: data type, uint32_t or unsigned int or size_t?

    // Check type of request (LURK extension and TLS extension)
    // TODO: switch or nested if ?
    if (request->header.extension.designation == LURK_EXTENSION_DESIGNATION) {
      if (request->header.type == LURK_TYPE_PING) {
        printf("Ping received: %" PRIu64 "\n", request->header.id);
        // Reuse all header except status
        memcpy(&(response.header), &(request->header), LURK_HEADER_LENGTH);
        response.header.status = LURK_STATUS_SUCCESS;
      }
    } else if (request->header.extension.designation == LURK_TLS12_EXTENSION_DESIGNATION) {
      printf("TLS12 received: %" PRIu64 "\n", request->header.id);
      //if (request->header.status == LURK_TLS12_STATUS_REQUEST)
      if (request->header.type == LURK_TLS12_TYPE_ECDHE) {
        // ECDHE -> hash and sign
        printf("LURK_TLS12_TYPE_ECDHE request\n");
        // Reuse all header except status
        memcpy(&(response.header), &(request->header), LURK_HEADER_LENGTH);
        response.header.status = LURK_TLS12_STATUS_SUCCESS;

        // Parse request
        struct lurk_tls12_ecdhe_req *ecdhe_req = (struct lurk_tls12_ecdhe_req *)&(request->payload);
  
        printf("Client random: ");
        int i;
        for (i = 0; i < LURK_TLS12_RANDOM_BYTES_LENGTH; i++) {
          printf("%x", ecdhe_req->base.client_random[i]);
        }
        printf("\nServer random: ");
        for (i = 0; i < LURK_TLS12_RANDOM_BYTES_LENGTH; i++) {
          printf("%x", ecdhe_req->base.server_random[i]);
        }
        printf("\n");
        printf("TLS min version: %d, TLS max version: %d\n", ecdhe_req->base.versions.minor, ecdhe_req->base.versions.major);
        printf("PRF algorithm: %d\n", ecdhe_req->base.prf_algorithm);

        printf("Proof of ownership: point_rG (%x), point_tG (%x)\n", ecdhe_req->poo_params.point_rG, ecdhe_req->poo_params.point_tG);
        
        // ECDHE data
        size_t ecdhe_params_size = 4 + ecdhe_req->ecdhe_params.public_length; // parameters + public (length for signature)
        printf("Curve type: %x, named curve: %x\n", ecdhe_req->ecdhe_params.curve_type, ntohs(ecdhe_req->ecdhe_params.named_curve));
        printf("ECDHE public key (%d): ", ecdhe_req->ecdhe_params.public_length);
        for (i = 0; i < ecdhe_req->ecdhe_params.public_length; i++) {
          printf("%02x", ecdhe_req->ecdhe_params.public[i]);
        }
        printf("\n");
        
        // Create ECDHE response
        struct lurk_tls12_ecdhe_res ecdhe_res;

        // Hash and sign with the given algorithms. TODO: Check if supported
        // Signature algorithms listed here: https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL) {
          printf("Error when creating context for digest\n");
          goto end; // TODO: Check frees
        }
  
        // Select hash
        const EVP_MD *md = NULL;
        switch (ecdhe_req->sig_algo.hash) {
          case 0:
            md = EVP_md_null(); // TODO: Check ?
            printf("NULL hash algorithm\n");
            break;
          case 1:
            md = EVP_md5();
            printf("MD5 hash algorithm\n");
            break;
          case 2:
            md = EVP_sha1();
            printf("SHA1 hash algorithm\n");
            break;
          case 3:
            md = EVP_sha224();
            printf("SHA224 hash algorithm\n");
            break;
          case 4:
            md = EVP_sha256();
            printf("SHA256 hash algorithm\n");
            break;
          case 5:
            md = EVP_sha384();
            printf("SHA384 hash algorithm\n");
            break;
          case 6:
            md = EVP_sha512();
            printf("SHA512 hash algorithm\n");
            break;
        }

        // Select signature (reference to a key previously read or NULL)
        EVP_PKEY *pkey_sign = NULL;
        // anonymous(0), rsa(1), dsa(2), ecdsa(3)
        switch (ecdhe_req->sig_algo.signature) {
          case 0:
            break; // ?
          case 1:
            pkey_sign = rsa_pkey;
            printf("RSA signature algorithm\n");
            break;
          case 2:
            break; // ?
          case 3:
            pkey_sign = ec_pkey;
            printf("ECDSA signature algorithm\n");
            break;
        }

        if (md == NULL || pkey_sign == NULL) {
          printf("Error when initializing hash or signature algorithm\n");
          // TODO: Send error message to client
          goto end;
        }
        
        unsigned int siglen;
        // Generate hash and sign, store in signed_params (max size -> last field so no problem)
        // signed_params has been allocated the maximun size, but it'll only send the needed bytes (siglen)
        if (EVP_SignInit_ex(mdctx, md, NULL) <= 0
            || EVP_SignUpdate(mdctx, &(ecdhe_req->base.client_random), LURK_TLS12_RANDOM_BYTES_LENGTH) <= 0
            || EVP_SignUpdate(mdctx, &(ecdhe_req->base.server_random), LURK_TLS12_RANDOM_BYTES_LENGTH) <= 0
            || EVP_SignUpdate(mdctx, &(ecdhe_req->ecdhe_params), ecdhe_params_size) <= 0 // TODO: Check key size
            || EVP_SignFinal(mdctx, (unsigned char *)&ecdhe_res.signed_params, &siglen, pkey_sign) <= 0) {
          printf("Error when signing parameters\n");
          goto end;
        }

        // Print (useful for debugging tools like wireshark)
        printf("Signed parameters (%d): ", siglen);
        for (i = 0; i < siglen; i++) {
          printf("%02x", ecdhe_res.signed_params[i]);
        }
        printf("\n\n");

        // Add payload and update length
        total_length = siglen; // payload length
        memcpy(&response.payload, &ecdhe_res, total_length);
        total_length += LURK_HEADER_LENGTH; // total packet length
        response.header.length = htonl(total_length);
      }
    }
    
    sendto(server_socket, &response, total_length, 0, (struct sockaddr *)&server_storage, addr_size);
  }

end:
  EVP_PKEY_free(ec_pkey);
  EVP_PKEY_free(rsa_pkey);
  return 0;
}