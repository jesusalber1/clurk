/*
 * Copyright (C) 2018 Orange
 * 
 * This software is distributed under the terms and conditions of the '2-Clause BSD License'
 * license which can be found in the file 'LICENSE' in this package distribution 
 * or at 'https://opensource.org/licenses/BSD-2-Clause'. 
 */
 
/*
 * LURK protocol implementation as defined in draft-mglt-lurk-lurk-00 and draft-mglt-lurk-tls12-00.
 * This file contains a simple LURK client over UDP:
 * 1. ECDHE client
 * 2. RSA client (server-side not developed yet, it cannot be tested)
 * 
 * TODO:
 * 0. (TODOs in comments)
 * 1. Capabilities
 * 2. Errors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "lurk.h"

int main(void) {
  // common variables
  unsigned char client_random[LURK_TLS12_RANDOM_BYTES_LENGTH];
  memset(client_random, 0x12, LURK_TLS12_RANDOM_BYTES_LENGTH);
  unsigned char server_random[LURK_TLS12_RANDOM_BYTES_LENGTH];
  memset(server_random, 0x34, LURK_TLS12_RANDOM_BYTES_LENGTH);
  /* 1. Test ECDHE handshake (both RSA and ECDSA) */
  // ecdhe variables
  unsigned char public[65];
  memset(public, 0x11, 65);
  unsigned char signed_params[LURK_TLS12_MAX_RSA_KEY_SIZE]; // static allocation (testing)
  size_t signed_length;
  
  if (lurk_client_ecdhe(client_random, server_random, 0x0017, 65, public, 0x00, 0x00, 0x06, 0x03, signed_params, &signed_length) == 1) {
    printf("Failed to sign parameters\n");
  }
  printf("Signed params (%ld): ", signed_length);
  int i;
  for (i = 0; i < signed_length; i++) {
    printf("%x", signed_params[i]);
  }
  printf("\n");
  
  /* 2. Test RSA handshake */
  /*
  // rsa variables
  unsigned char enc_premaster[LURK_TLS12_MAX_RSA_KEY_SIZE];
  memset(enc_premaster, 0x11, LURK_TLS12_MAX_RSA_KEY_SIZE);
  unsigned char master_secret[LURK_TLS12_RSA_MASTER_SIZE]; // static allocation (testing)

  if (lurk_client_rsa(client_random, server_random, enc_premaster, premaster_len, master_secret) == 1) {
    printf("Failed to receive master secret\n");
  }
  printf("Master secret\n");
  int i;
  for (i = 0; i < LURK_TLS12_RSA_MASTER_SIZE; i++) {
    printf("%x", master_secret[i]);
  }
  printf("\n");*/

  return 0;
}