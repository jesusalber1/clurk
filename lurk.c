/*
 * Copyright (C) 2018 Orange
 * 
 * This software is distributed under the terms and conditions of the '2-Clause BSD License'
 * license which can be found in the file 'LICENSE' in this package distribution 
 * or at 'https://opensource.org/licenses/BSD-2-Clause'. 
 */

/*
 * LURK protocol implementation as defined in draft-mglt-lurk-lurk-00 and draft-mglt-lurk-tls12-00.
 * This file contains a simple implmentation of LURK extension and LURK TLS12 extension over UDP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include "lurk.h"

// Constants
#define BUFFER_MAX_LENGTH 1500 // for reception (TODO: How much? or dynamic)
const size_t LURK_TLS12_MAX_SIGNATURE_SIZE = LURK_TLS12_MAX_RSA_KEY_SIZE;

/*
 * Create UDP socket
 * Returned values:
 *  Success: 0
 *  Error: 1
 */
int lurk_init_socket(int *client_socket, struct sockaddr_in *server_addr, socklen_t *addr_size) {
  // Get server address and port from environment variables
  const char *server_addr_str = getenv("LURK_SERVER_ADDR");
  const char *server_port_str = getenv("LURK_SERVER_PORT");
  if ((server_addr_str == NULL) || (server_port_str == NULL)) {
    printf("Error: LURK server address or port not defined. Use env 'LURK_SERVER_ADDR' and 'LURK_SERVER_PORT'.\n");
    return 1;
  }

  short server_port = atoi(server_port_str);
  // Create UDP socket
  if ((*client_socket = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    return 1;
  }
  
  // Configure settings in address struct
  server_addr->sin_family = AF_INET;
  server_addr->sin_port = htons(server_port);
  server_addr->sin_addr.s_addr = inet_addr(server_addr_str);
  memset(server_addr->sin_zero, '\0', sizeof server_addr->sin_zero);
  
  // Initialize size variable to be used in reception
  *addr_size = sizeof *server_addr;

  return 0;
}

/* 
 * LURK client ECDHE -> request for signature
 * Valid return values:
 *  Success: 0
 *  Error: 1
 */
int lurk_client_ecdhe(uint8_t *client_random, uint8_t *server_random, /*uint8_t curve_type,*/
                      uint16_t named_curve, uint8_t public_length, uint8_t *public, uint8_t point_rG, 
                      uint8_t point_tG, uint8_t sig_hash, uint8_t sig_sig, uint8_t *signed_params, size_t *signed_length) {

  // UDP socket variables
  int client_socket;
  struct sockaddr_in server_addr;
  socklen_t addr_size = sizeof server_addr;

  // Init socket
  if (lurk_init_socket(&client_socket, &server_addr, &addr_size) == 1) {
    printf("Failed to initialize socket\n");
    return 1;
  }

  // Create TLS12 Request
  struct lurk_pdu request;
  request.header.extension.designation = LURK_TLS12_EXTENSION_DESIGNATION;
  request.header.extension.version = LURK_TLS12_EXTENSION_VERSION;
  request.header.status = LURK_TLS12_STATUS_REQUEST;
  request.header.type = LURK_TLS12_TYPE_ECDHE;
  // 8 random bytes for id (uint64_t)
  // TODO: Check if other random generators are suitable? (OpenSSL would be but we have to link it)
  FILE *f;
  f = fopen("/dev/urandom", "r");
  fread(&(request.header.id), sizeof(request.header.id), 1, f);
  fclose(f);

  // Create ECDHE Request
  struct lurk_tls12_ecdhe_req ecdhe_req;
  // base
  ecdhe_req.base.key_pair_id_type = LURK_TLS12_KEY_PAIR_ID_SHA256_32; // TODO: Add key pair type
  ecdhe_req.base.key_pair_id = htonl(0x00); // TODO: Add key pair id
  memcpy(&ecdhe_req.base.client_random, client_random, LURK_TLS12_RANDOM_BYTES_LENGTH);
  memcpy(&ecdhe_req.base.server_random, server_random, LURK_TLS12_RANDOM_BYTES_LENGTH);
  // base.versions
  ecdhe_req.base.versions.major = LURK_TLS12_TLS_VERSION_MIN;
  ecdhe_req.base.versions.minor = LURK_TLS12_TLS_VERSION_MAJ;
  ecdhe_req.base.prf_algorithm = LURK_TLS12_POOPRF_NULL;
  // poo_params
  ecdhe_req.poo_params.point_rG = point_rG;
  ecdhe_req.poo_params.point_tG = point_tG;
  // signature algorithms
  ecdhe_req.sig_algo.hash = sig_hash;
  ecdhe_req.sig_algo.signature = sig_sig;
  // ecdhe_params (variable)
  ecdhe_req.ecdhe_params.curve_type = LURK_TLS12_CURVE_TYPE_NAMED; // curve_type; ?
  ecdhe_req.ecdhe_params.named_curve = htons(named_curve); // only named curves supported by OpenSSL
  ecdhe_req.ecdhe_params.public_length = public_length;
  memcpy(&(ecdhe_req.ecdhe_params.public), public, public_length);
  
  // Add payload and update length
  // TODO: data type, uint32_t or unsigned int or size_t ?
  uint32_t total_length = LURK_TLS12_SIZE_WITHOUT_PUBLIC + public_length; // payload length
  memcpy(&request.payload, &ecdhe_req, total_length);
  total_length += LURK_HEADER_LENGTH; // total packet length
  request.header.length = htonl(total_length);

  // TODO: Create a generic 'send_and_receive' function?

  // Send message to LURK server
  sendto(client_socket, &request, total_length, 0, (struct sockaddr *)&server_addr, addr_size);

  // Receive response from server (client-server schema)
  unsigned char buffer[BUFFER_MAX_LENGTH];
  int recv_bytes;

  for (;;) {
    // Receive data from UDP socket (blocking) -> Fix this
    recv_bytes = recvfrom(client_socket, buffer, BUFFER_MAX_LENGTH, 0, (struct sockaddr *)&server_addr, &addr_size);
    if (recv_bytes < LURK_HEADER_LENGTH) {
      continue;
    }
    // Parse response as lurk_pdu
    struct lurk_pdu *response = (struct lurk_pdu *)buffer;

    // Good response ?
    if (response->header.id == request.header.id && response->header.type == request.header.type) {
      // What type?
      if (response->header.status == LURK_TLS12_STATUS_SUCCESS) {
        struct lurk_tls12_ecdhe_res *ecdhe_res = (struct lurk_tls12_ecdhe_res *)&(response->payload);
        size_t siglen = ntohl(response->header.length) - LURK_HEADER_LENGTH;
        // Copy results
        memcpy(signed_params, &(ecdhe_res->signed_params), siglen);
        *signed_length = siglen;
      } else {
        printf("Error (or unexpected packet) received from LURK server\n");
        return 1;
      }
      break; // Go out of the loop even if there's an error (the id and type mean that the packet was the expected one)
    }
  }

  return 0;
}

/* 
 * TODO: This functionality will be added when implemented on the server side ...
 *
 * LURK client RSA -> request for master key
 * Valid return values:
 *  Success: 0
 *  Error: 1
 */
/*int lurk_client_rsa(uint8_t *client_random, uint8_t *server_random, uint8_t *enc_premaster, size_t premaster_length, uint8_t *master_secret) {

  // UDP socket variables
  int client_socket;
  struct sockaddr_in server_addr;
  socklen_t addr_size = sizeof server_addr;

  // Init socket
  if (lurk_init_socket(&client_socket, &server_addr, &addr_size) == 1) {
    printf("Failed to initialize socket\n");
    return 1;
  }

  // Create TLS12 Request
  struct lurk_pdu request;
  request.header.extension.designation = LURK_TLS12_EXTENSION_DESIGNATION;
  request.header.extension.version = LURK_TLS12_EXTENSION_VERSION;
  request.header.status = LURK_TLS12_STATUS_REQUEST;
  request.header.type = LURK_TLS12_TYPE_RSA_MASTER;
  // 8 random bytes for id (uint64_t)
  // TODO: Check if other random generators ? (try to avoid OpenSSL...)
  FILE *f;
  f = fopen("/dev/urandom", "r");
  fread(&(request.header.id), sizeof(request.header.id), 1, f);
  fclose(f);

  // Create ECDHE Request
  struct lurk_tls12_rsa_master_req rsa_req;
  // base
  rsa_req.base.key_pair_id_type = LURK_TLS12_KEY_PAIR_ID_SHA256_32; // TODO: Add key pair type
  rsa_req.base.key_pair_id = htonl(0x00); // TODO: Add key pair id
  memcpy(&rsa_req.base.client_random, client_random, LURK_TLS12_RANDOM_BYTES_LENGTH);
  memcpy(&rsa_req.base.server_random, server_random, LURK_TLS12_RANDOM_BYTES_LENGTH);
  // base.versions
  rsa_req.base.versions.major = LURK_TLS12_TLS_VERSION_MIN;
  rsa_req.base.versions.minor = LURK_TLS12_TLS_VERSION_MAJ;
  rsa_req.base.prf_algorithm = LURK_TLS12_POOPRF_NULL;
  // encrypted premaster secret
  memcpy(&(rsa_req.enc_premaster), enc_premaster, premaster_length);
  
  // Add payload and update length
  // TODO: data type, uint32_t or unsigned int or size_t ?
  uint32_t total_length = LLURK_TLS12_BASE_SIZE + premaster_length; // payload length
  memcpy(&request.payload, &rsa_req, total_length);
  total_length += LURK_HEADER_LENGTH; // total packet length
  request.header.length = htonl(total_length);

  // TODO: Create a generic 'send_and_receive' function

  // Send message to LURK server
  sendto(client_socket, &request, total_length, 0, (struct sockaddr *)&server_addr, addr_size);

  // Receive response from server (client-server schema)
  unsigned char buffer[BUFFER_MAX_LENGTH];
  int recv_bytes;

  for (;;) {
    // Receive data from UDP socket (blocking) -> Fix this
    recv_bytes = recvfrom(client_socket, buffer, BUFFER_MAX_LENGTH, 0, (struct sockaddr *)&server_addr, &addr_size);
    if (recv_bytes < LURK_HEADER_LENGTH) {
      continue;
    }
    // Parse response as lurk_pdu
    struct lurk_pdu *response = (struct lurk_pdu *)buffer;

    // Good response ?
    if (response->header.id == request.header.id && response->header.type == request.header.type) {
      // What type?
      if (response->header.status == LURK_TLS12_STATUS_SUCCESS) {
        struct lurk_tls12_rsa_master_res *rsa_res = (struct lurk_tls12_rsa_master_res *)&(response->payload);
        // Copy result
        memcpy(master_secret, &(rsa_res->master_secret), LURK_TLS12_RSA_MASTER_SIZE);
      } else {
        printf("Error (or unexpected packet) received from LURK server\n");
        return 1;
      }
      break; // Go out of the loop even if there's an error (the id and type mean that the packet was the expected one)
    }
  }

  return 0;
}*/

