/*
 * Copyright (C) 2018 Orange
 * 
 * This software is distributed under the terms and conditions of the '2-Clause BSD License'
 * license which can be found in the file 'LICENSE' in this package distribution 
 * or at 'https://opensource.org/licenses/BSD-2-Clause'. 
 */
 
/*
 * LURK protocol implementation as defined in draft-mglt-lurk-lurk-00 and draft-mglt-lurk-tls12-00.
 * This file contains all constants and headers for LURK protocol <-> LURK extension and LURK TLS12 extension
 */

#ifndef _LURK_H
#define _LURK_H

/*
 * Note: One-field structures (as defined in draft) are directly declared in the final packet structure.
 * Note: No typedefs yet (always use struct).
 * Note: Packed attribute is required to avoid data structure padding, see https://gcc.gnu.org/onlinedocs/gcc-3.3/gcc/Type-Attributes.html
 * Note: The idea is to use pointers for variable length fields (dynamic allocation instead of static)
 */


/* 1. LURK protocol <-> LURK extension */
#define LURK_HEADER_LENGTH              16
#define LURK_MAX_PAYLOAD_LENGTH         1484 // 1500 - 16 (TODO: Compute the actual value)
// LURK extension
#define LURK_EXTENSION_DESIGNATION      0x00
#define LURK_EXTENSION_VERSION          0x01
// LURKStatus (enum is not used because its size is 4 bytes instead of 1)
#define LURK_STATUS_REQUEST             0x00
#define LURK_STATUS_SUCCESS             0x01
#define LURK_STATUS_UNDEFINED_ERROR     0x02
#define LURK_STATUS_INVALID_FORMAT      0x03
#define LURK_STATUS_INVALID_EXTENSION   0x04
#define LURK_STATUS_INVALID_TYPE        0x05
#define LURK_STATUS_STATUS              0x06
#define LURK_STATUS_TEMPORARY_FAILURE   0x07 // TODO: fix this value on the draft (currently 0x06)
// LURKType
#define LURK_TYPE_CAPABILITIES          0x00
#define LURK_TYPE_PING                  0x01
// Request Payload Response max lengths
#define LURK_MAX_SUPPORTED_EXTENSIONS   16 // TODO: Check it out
//#define LURK_MAX_SUPPORTED_TYPES 16 // TODO: Check it out (does it still exist?)

/* 1.1 Lurk packet */
/* Lurk extension structure (used in lurk header and capabilities) */
struct lurk_extension {
  uint8_t designation;
  uint8_t version;
} __attribute__((packed));

/* Lurk header structure */
struct lurk_header {
  struct lurk_extension extension;
  uint8_t status; // defined by the extension
  uint8_t type;   // defined by the extension
  uint64_t id;
  uint32_t length;
} __attribute__((packed));

/* Lurk packet (header + payload), payload may be empty */
struct lurk_pdu {
  struct lurk_header header;
  unsigned char payload[LURK_MAX_PAYLOAD_LENGTH]; // TODO: Try to use pointers (dynamic allocation instead of static)
} __attribute__((packed));

/* 1.2 Lurk capabilities (not implemented/tested yet) */
/* Lurk Request payload is empty in both capabilities and ping types */
/* Lurk Response payload */
struct lurk_cap_res {
  struct lurk_extension supported_extensions_list[LURK_MAX_SUPPORTED_EXTENSIONS];
  // lurk supported types? I think this value is not used anymore
  uint32_t lurk_state; // I'd invert the order so parsing would be easier (fixed first and variable after)
};

/* 1.3 Lurk errors (not implemented/tested yet) */
/* Lurk error payload */
struct lurk_error_payload {
  uint32_t lurk_state;
};


/* 2. TLS12 extension */
// TLS12 extension
#define LURK_TLS12_EXTENSION_DESIGNATION          0x01
#define LURK_TLS12_EXTENSION_VERSION              0x01
// TLS12Status
#define LURK_TLS12_STATUS_REQUEST                 0x00
#define LURK_TLS12_STATUS_SUCCESS                 0x01
#define LURK_TLS12_STATUS_UNDEFINED_ERROR         0x02
#define LURK_TLS12_STATUS_INVALID_PAYLOAD         0x03
#define LURK_TLS12_STATUS_INVALID_KEY_TYPE        0x04
#define LURK_TLS12_STATUS_INVALID_KEY_ID          0x05
#define LURK_TLS12_STATUS_INVALID_TLS_VERSION     0x06
#define LURK_TLS12_STATUS_INVALID_TLS_RANDOM      0x07
#define LURK_TLS12_STATUS_INVALID_PRF             0x08
#define LURK_TLS12_STATUS_INVALID_ENC_PREMASTER   0x09
#define LURK_TLS12_STATUS_INVALID_EC_TYPE         0x0A
#define LURK_TLS12_STATUS_INVALID_EC_BASICTYPE    0x0B
#define LURK_TLS12_STATUS_INVALID_EC_CURVE        0x0C
#define LURK_TLS12_STATUS_INVALID_EC_POINT_FORMAT 0x0D
#define LURK_TLS12_STATUS_INVALID_POO_PRF         0x8A
#define LURK_TLS12_STATUS_INVALID_POO             0x8B
// TLS12Type
#define LURK_TLS12_TYPE_CAPABILITIES              0x00
#define LURK_TLS12_TYPE_PING                      0x01
#define LURK_TLS12_TYPE_RSA_MASTER                0x02
#define LURK_TLS12_TYPE_RSA_EXTENDED_MASTER       0x03
#define LURK_TLS12_TYPE_ECDHE                     0x04
// TLS12Base
#define LURK_TLS12_TLS_VERSION_MIN                0x03
#define LURK_TLS12_TLS_VERSION_MAJ                0x03
#define LURK_TLS12_KEY_PAIR_ID_SHA256_32          0x00
#define LURK_TLS12_RANDOM_BYTES_LENGTH            32 // 32 bytes as specified in RFC5246 section 7.4.1.3 (gmt_unix_time + random)
#define LURK_TLS12_PRF_SHA256_NULL                0x00
#define LURK_TLS12_PRF_SHA256_SHA256              0x01

/* Protocol version (same as in TLS) */
struct lurk_tls12_tls_prot_ver {
  uint8_t major;
  uint8_t minor;
} __attribute__((packed));

/* TLS12 base structure */
struct lurk_tls12_base {
  uint8_t key_pair_id_type;
  uint32_t key_pair_id; // 32 first bits of the hash of the public key using sha256 (SNI instead?)
  uint8_t client_random[LURK_TLS12_RANDOM_BYTES_LENGTH];
  uint8_t server_random[LURK_TLS12_RANDOM_BYTES_LENGTH];
  struct lurk_tls12_tls_prot_ver versions;
  uint8_t prf_algorithm;
} __attribute__((packed));

/* 2.1 rsa_master (not implemented/tested yet) */
#define LURK_TLS12_MAX_RSA_KEY_SIZE   512  // 4096 bits = 512 Bytes (normally 256) TODO: Check openssl/rsa.h (includes) where #define OPENSSL_RSA_MAX_MODULUS_BITS 16384
#define LURK_TLS12_RSA_MASTER_SIZE    48 // the size of the master secret (and premaster secret) is always 48 bytes
#define LLURK_TLS12_BASE_SIZE         (8 + 2*LURK_TLS12_RANDOM_BYTES_LENGTH) // (8 + 2*SSL_RANDOMS) base

// Request
struct lurk_tls12_rsa_master_req {
  struct lurk_tls12_base base;
  // TODO: [Important!] add variable to store enc_premaster length (depends on max size... how many bytes?)
  uint8_t enc_premaster[LURK_TLS12_MAX_RSA_KEY_SIZE]; // 512 bytes maximum
} __attribute__((packed));

// Response
struct lurk_tls12_rsa_master_res {
  uint8_t master_secret[LURK_TLS12_RSA_MASTER_SIZE];
} __attribute__((packed));

/* 2.2 rsa_extended_master (not implemented/tested yet) */
/* -- */

/* 2.3 ecdhe (not implemented/tested yet) */
#define LURK_TLS12_POOPRF_NULL        0x00
#define LURK_TLS12_POOPRF_SHA256_128  0x01
#define LURK_TLS12_POOPRF_SHA256_256  0x01

/* This structure is defined in RFC 4492 Section 5.4. There are 3 cases but OpenSSL
 * only supports 'named curves' so this is the only one I've developed here (simplicity)
 */
// TODO: Extend to all 3 cases?
// ECParameters just contains curve type and the named curve (otherwise it'd be useful to define a new struct)
#define LURK_TLS12_CURVE_TYPE_EXP_PRIME   0x01
#define LURK_TLS12_CURVE_TYPE_EXP_CHAR2   0x02
#define LURK_TLS12_CURVE_TYPE_NAMED       0x03
#define LURK_TLS12_MAX_ECDSA_KEY_SIZE     145 // Largest curve is sect571k1: 571 bits -> (ceil(571/8)) = 72 bytes => Key size = 72*2 + 1
// See RFC 4492 Section 5.1.1 to check supported ECC curves in TLS. Size is computed as explained here https://stackoverflow.com/a/6687080

// ECDHE parameters
struct lurk_tls12_ecdhe_params {
  uint8_t curve_type;
  uint16_t named_curve; // 2 bytes as defined in RFC 4492 Section 5.1.1
  uint8_t public_length; // 1 byte to indicate the length of public key
  uint8_t public[LURK_TLS12_MAX_ECDSA_KEY_SIZE]; // Ephemeral ECDH public key
} __attribute__((packed));

// Signature algorithms (separate structure because ecdhe_params is used by the signature): hash algo + signature algo (RFC 4492 Section 5.4)
struct lurk_tls12_sig_algo {
  uint8_t hash;
  uint8_t signature;
} __attribute__((packed));

// Proof of ownership
struct lurk_tls12_poo_params {
  uint8_t point_rG; // 1 byte (RFC 4492 Section 5.4)
  uint8_t point_tG; // 1 byte (RFC 4492 Section 5.4)
} __attribute__((packed));

// Request
#define LURK_TLS12_SIZE_WITHOUT_PUBLIC  (8 + 2*LURK_TLS12_RANDOM_BYTES_LENGTH) + 2 + 2 + 4 // (8 + 2*SSL_RANDOMS) base + 2 poo params + 2 signature algorithms + 4 ecdhe params (without public)
struct lurk_tls12_ecdhe_req {
  struct lurk_tls12_base base;
  struct lurk_tls12_poo_params poo_params;
  struct lurk_tls12_sig_algo sig_algo;
  struct lurk_tls12_ecdhe_params ecdhe_params;
} __attribute__((packed));

// Response
/* We allocate the maximun size (ECDSA or RSA signatures may be used).
 * Use LURK_TLS12_MAX_RSA_KEY_SIZE because RSA signatures are always larger
 */
struct lurk_tls12_ecdhe_res {
  // TODO: [Important!] add variable to store signed_params length (depends on max size... how many bytes?)
  uint8_t signed_params[LURK_TLS12_MAX_RSA_KEY_SIZE]; 
} __attribute__((packed));

/* 2.4 capabilities (not implemented/tested yet) */
/* -- */


/* API */
// Constants (is this correct? useful for client to allocate memory -> OpenSSL constants may be used instead)
const size_t LURK_TLS12_MAX_SIGNATURE_SIZE; // = LURK_TLS12_MAX_RSA_KEY_SIZE

// Functions
// LURK client ECDHE
int lurk_client_ecdhe(uint8_t *client_random, uint8_t *server_random, /*uint8_t curve_type,*/
                      uint16_t named_curve, uint8_t public_length, uint8_t *public, uint8_t point_rG, 
                      uint8_t point_tG, uint8_t sig_hash, uint8_t sig_sig, uint8_t *signed_params, size_t *signed_length);

// LURK client RSA
//int lurk_client_rsa(uint8_t *client_random, uint8_t *server_random, uint8_t *enc_premaster, size_t premaster_length, uint8_t *master_secret);

#endif