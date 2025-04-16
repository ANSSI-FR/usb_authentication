/**
 * @file policy_engine.c
 *
 * @brief Simple USB userspace policy engine, it responds to the following requests:
 *  - CHECK_DIGEST
 *  - CHECK_CERTIFICATE
 *  - GENERATE_NONCE
 *  - CHECK_CHALLENGE
 *  - REMOVE_DEVICE
 *
 * @author Luc Bonnafoux <luc.bonnafoux@ssi.gouv.fr>
 * @author Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 *
 * SPDX-FileCopyrightText: © 2025 ANSSI
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/queue.h>
#include <dirent.h>
#include <arpa/inet.h>

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>

#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/psa_util.h"
#include "mbedtls/entropy.h"

#include "psa/crypto.h"
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"

#include "usb_auth_netlink.h"

#define unlikely(x)     __builtin_expect((x),0)

/**
 * Generic Netlink family used for exchanges with the kernel
 */
static int fam = 0;
/**
 * Handle to the unicast socket with the kernel
 */
static struct nl_sock *ucsk = NULL;

/**
 * Handle to random generator
 */
static mbedtls_ctr_drbg_context ctr_drbg;

////////////////////////////////////////////////////////////////////////////////
//
// Data management functions
//
// TODO: improve locking mechanism: add per-entity mutex
//
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Root CA certificates are loaded upon policy engine initialization
 */
typedef struct usb_auth_root_ca {
  uint8_t digest[32]; /**< 32 byte hash of the Root signing certificate, big endian */
  mbedtls_x509_crt *ctx; /**< public signing key */
  uint8_t blocked; /**< 1 if the certificate has been blacklisted */
  LIST_ENTRY(usb_auth_root_ca) next;
} usb_auth_root_ca_t;

LIST_HEAD(usb_auth_root_store, usb_auth_root_ca);
static struct usb_auth_root_store usb_auth_root_store_head;

/**
 * @brief Insert a new root certificate in the list of trusted certificates
 *
 * Possible error codes:
 *  - EINVAL : invalid digest or key
 *  - ENOMEM : failed to allocate new element
 *
 * @param [in] digest : hash of the certificate
 * @param [in] ctx    : public signing key contained in the certificate
 *
 * @return 0 on SUCCESS or error code
 */
static int usb_auth_insert_root_ca(const uint8_t *const digest, mbedtls_x509_crt *ctx)
{
  usb_auth_root_ca_t *root_ca = NULL;

  if (unlikely(NULL == digest || NULL == ctx)) {
    fprintf(stderr, "usb_auth_insert_root_ca: invalid arguments\n");
    return -EINVAL;
  }

  if (NULL == (root_ca = malloc(sizeof(usb_auth_root_ca_t)))) {
    fprintf(stderr, "usb_auth_insert_root_ca: failed to allocate new root CA\n");
    return -ENOMEM;
  }

  memcpy(root_ca->digest, digest, 32);
  root_ca->ctx = ctx;
  root_ca->blocked = 0;

  LIST_INSERT_HEAD(&usb_auth_root_store_head, root_ca, next);

  return 0;
}

/**
 * @brief Find a root ca
 *
 * @param [in] digest   : 32 byte root certificate digest
 * @param [out] root_ca : handle to the root certificate
 *
 * @return 0 on SUCCESS or an error code
 */
static int usb_auth_find_root_ca(const uint8_t *const digest, usb_auth_root_ca_t **root_ca)
{
  usb_auth_root_ca_t *ca = NULL;

  if (unlikely(NULL == digest || NULL == root_ca)) {
    return -1;
  }

  // ca->digest is valid
  // digest, which is root_hash from header has two last bytes invalid.
  LIST_FOREACH(ca, &usb_auth_root_store_head, next) {
    if (!memcmp(ca->digest, digest, 32)) {
      *root_ca = ca;
      return 0;
    }
  }

  return -1;
}

/**
 * @brief Destroy the root CA list
 */
static void usb_auth_free_root_list(void)
{
  usb_auth_root_ca_t *root_ca = NULL;

  LIST_FOREACH(root_ca, &usb_auth_root_store_head, next) {
    if (root_ca->ctx) {
      mbedtls_x509_crt_free(root_ca->ctx);
    }

    LIST_REMOVE(root_ca, next);
  }
}

/**
 * @brief Known device certificates are stored in usb_auth_dev_slot.
 *
 * They are created upon successful validation of a device certificate chain
 * with a CHECK_CERTIFICATE request from the kernel.
 */
typedef struct usb_auth_dev_slot {
  uint8_t blocked; /**< 1 if the certificate has been blacklisted */
  uint8_t digest[32]; /**< 32 byte hash of the certificate chain, big endian */
  mbedtls_x509_crt *ctx; /**< public signing key of the device (extracted from leaf certificate) */
  psa_key_id_t key_id;
  LIST_ENTRY(usb_auth_dev_slot) next;
} usb_auth_dev_slot_t;

LIST_HEAD(usb_auth_known_slots, usb_auth_dev_slot);
static struct usb_auth_known_slots usb_auth_known_slots_head;
static pthread_mutex_t usb_auth_known_slots_mut = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Create a new slot and add it to the list
 *
 * WARNING: This function might block on the list mutex
 *
 * Possible error codes:
 *  - EINVAL : invalid slots
 *  - ENOMEM : failed to allocate new device structure
 *
 * @param [in] digest : 32 byte hash of the certificate chain
 * @param [in] ctx    : public signing key associated to the slot
 * @param [out] slot  : handle to the newly created slot
 *
 * @return 0 on SUCCESS or error code
 */
static int usb_auth_add_slot(const uint8_t *const digest, mbedtls_x509_crt *ctx,
                            const psa_key_id_t key_id, usb_auth_dev_slot_t **slot)
{
  usb_auth_dev_slot_t *dev_slot = NULL;

  if (unlikely(NULL == digest || ctx == NULL || NULL == slot)) {
    fprintf(stderr, "usb_auth_add_slot: invalid parameters\n");
    return -EINVAL;
  }

  if (NULL == (dev_slot = malloc(sizeof(usb_auth_dev_slot_t)))) {
    fprintf(stderr, "usb_auth_add_slot: failed to allocate new slot\n");
    return -ENOMEM;
  }


  memcpy(dev_slot->digest, digest, 32);

  dev_slot->ctx = ctx;
  dev_slot->key_id = key_id;
  dev_slot->blocked = 0;

  pthread_mutex_lock(&usb_auth_known_slots_mut);
  LIST_INSERT_HEAD(&usb_auth_known_slots_head, dev_slot, next);
  pthread_mutex_unlock(&usb_auth_known_slots_mut);

  *slot = dev_slot;

  return 0;
}

/**
 * @brief Device context
 *
 * They are created after a successful CHECK_DIGEST or CHECK_CERTIFICATE request.
 * They are removed with a REMOVE_DEVICE request from kernel.
 */
typedef struct usb_auth_device {
  uint32_t id; /**< 32 bit unique ID for the device, supplied by the kernel */
  uint8_t nonce[32]; /**< 32 byte nonce used for the challenge */
  usb_auth_dev_slot_t *slots[8]; /**< Slots known for the device or NULL */
  uint8_t authorized; /**< 1 if the device has been authorized */
  uint8_t authenticated; /**< 1 if the device has been authenticated */
  LIST_ENTRY(usb_auth_device) next;
} usb_auth_device_t;

LIST_HEAD(usb_auth_devices, usb_auth_device);
static struct usb_auth_devices usb_auth_devs_head;
static pthread_mutex_t usb_auth_devs_mut = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Create a new device and add it to the list
 *
 * WARNING: This function might block on the list mutex
 *
 * Possible error codes:
 *  - EINVAL : invalid slots
 *  - ENOMEM : failed to allocate new device structure
 *
 * @param [in] id    : unique identifier for the new device
 * @param [in] slots : pointer to known slots for the device
 *
 * @return 0 on SUCCESS or error code
 */
static int usb_auth_add_device(const uint32_t id, const usb_auth_dev_slot_t *const slots[8])
{
  usb_auth_device_t *dev = NULL;

  if (unlikely(NULL == slots)) {
    fprintf(stderr, "usb_auth_add_device: invalid parameters\n");
    return -EINVAL;
  }

  if (NULL == (dev = malloc(sizeof(usb_auth_device_t)))) {
    fprintf(stderr, "usb_auth_add_device: failed to allocate new device\n");
    return -ENOMEM;
  }

  dev->id = id;
  memcpy(dev->slots, slots, sizeof(usb_auth_dev_slot_t *)*8);
  memset(dev->nonce, 0, 32);
  dev->authorized = 0;
  dev->authenticated = 0;

  pthread_mutex_lock(&usb_auth_devs_mut);
  LIST_INSERT_HEAD(&usb_auth_devs_head, dev, next);
  pthread_mutex_unlock(&usb_auth_devs_mut);

  return 0;
}

/**
 * @brief Try to find a device in the list
 *
 * WARNING: this function might block on the list mutex
 *
 * @param [in] id   : identifier to look for
 * @param [out] dev : device handle if found
 *
 * @return 0 on SUCCESS else an error code
 */
static int usb_auth_get_device(const uint32_t id, usb_auth_device_t **dev)
{
  usb_auth_device_t *item = NULL;

  pthread_mutex_lock(&usb_auth_devs_mut);
  LIST_FOREACH(item, &usb_auth_devs_head, next) {
    if (item->id == id) {
      *dev = item;
      pthread_mutex_unlock(&usb_auth_devs_mut);
      return 0;
    }
  }
  pthread_mutex_unlock(&usb_auth_devs_mut);

  return -1;
}

/**
 * @brief remove a device from the list
 *
 * WARNING: this function might block on the list mutex
 *
 * @param [in] id : unique identifier for the device, supplied by the kernel
 *
 * @return 0 on SUCCESS or an error code
 */
static int usb_auth_remove_device(const uint32_t id)
{
  usb_auth_device_t *dev = NULL;

  pthread_mutex_lock(&usb_auth_devs_mut);
  LIST_FOREACH(dev, &usb_auth_devs_head, next) {
    if (dev->id == id) {
      LIST_REMOVE(dev, next);
    }
  }
  pthread_mutex_unlock(&usb_auth_devs_mut);

  return -1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Cryptographic functions
//
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Try to load a Root CA certificate from a PEM file
 *
 * Possible error code:
 *  - EINVAL : invalid path suupplied
 *
 * @param [in] path : path to the PEM file containing the certificate
 *
 * @return 0 on SUCCESS or error code
 */
static int load_root_ca(const char *const path)
{
  int ret = 0;
  mbedtls_x509_crt *root_crt = NULL;
  uint8_t hash[32] = {0};
  char buf[1024] = {0};


  if (NULL == path) {
    fprintf(stderr, "load_root_ca: Invalid parameters\n");
    ret = -EINVAL;
    goto cleanup;
  }

  if (NULL == (root_crt = malloc(sizeof(mbedtls_x509_crt)))) {
    fprintf(stderr, "load_root_ca: failed to allocate root context\n");
    ret = -ENOMEM;
    goto cleanup;
  }

  mbedtls_x509_crt_init(root_crt);

  if (0 != (ret = mbedtls_x509_crt_parse_file(root_crt, path))) {
    fprintf(stderr, "load_root_ca: Failed to parse root certificate, ret: %d\n", ret);
    ret = -EINVAL;
    free(root_crt);
    goto cleanup;
  }

  mbedtls_sha256(root_crt->raw.p, root_crt->raw.len, hash, 0);

  mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", root_crt);
  fprintf(stderr, "Root certificate\n%s", buf);

  // Add new root CA to the list
  if (0 != usb_auth_insert_root_ca(hash, root_crt)) {
    fprintf(stderr, "load_root_ca: failed to add new root ca to the list\n");
    ret = -1;
    free(root_crt);
    goto cleanup;
  }

  ret = 0;

cleanup:

  return ret;
}

#define ASN1_SEQUENCE 0x30

/**
 * @brief extract the length of a TLV
 *
 * @param [in] chain : sequence to extract
 *
 * @return the length in byte
 */
static uint16_t get_asn1_length(const uint8_t *const chain)
{
  uint8_t nb_bytes = 0;

  if (127 > chain[0]) {
    return (uint16_t) chain[0] + 2; // +2: TL
  } else {
    nb_bytes = chain[0] & 0x7F;

    if (nb_bytes > 2) {
      // Length too big for a certificate
      return 0;
    }

    return ntohs(((uint16_t *)(chain+1))[0]) + 4; // +4: TL
  }
}

/**
 * @brief Validate USB authentication custom x509 extension
 *
 * FIXME: for now only validate all extensions
 */
int x509_crt_ext_cb(void *p_ctx, mbedtls_x509_crt const *crt,
  mbedtls_x509_buf const *oid, int critical,
  const unsigned char *p, const unsigned char *end)
{
  (void) p_ctx;
  (void) crt;
  (void) p;
  (void) end;

  size_t i = 0;

  fprintf(stderr, "x509_crt_ext_cb: entry\n");
  fprintf(stderr, "is_critical: %d\n", critical);
  fprintf(stderr, "Tag: %d\n", oid->tag);
  fprintf(stderr, "Length: %lu\n", oid->len);
  fprintf(stderr, "Value: \n");
  for (i = 0; i < oid->len; i++) {
    fprintf(stderr, "%02x ", oid->p[i]);
  }
  fprintf(stderr, "\n");


  // Always validate extension
  return 0;
}

/**
 * @brief Validate a certificate chain and extract the public signing key
 *
 * Possible error codes:
 *  - EINVAL : invalid arguments
 *  - ENOMEM : unable to allocate new key
 *
 * @param [in] root_key : Root CA public signing key
 * @param [in] chain    : certificate chain starting at the first certificate
 * @param [in] len      : length of the certificate chain
 * @param [out] ctx     : extract public signing key
 *
 * @return 0 on SUCCESS or error code
 */
static int validate_cert_chain(mbedtls_x509_crt *root_crt,
                               const uint8_t *const chain, const uint16_t len,
                               mbedtls_x509_crt **leaf_crt, psa_key_id_t *key_id)
{
  int ret = 0;
  uint16_t offset = 0;
  uint16_t cert_len = 0;
  mbedtls_x509_crt *parent_crt = NULL;
  mbedtls_x509_crt *child_crt = NULL;
  char buf[1024] = {0};
  uint32_t flags = 0;

  if (unlikely(NULL == root_crt || NULL == chain || NULL == leaf_crt)) {
    fprintf(stderr, "validate_cert_chain: invalid arguments\n");
    return -EINVAL;
  }

  parent_crt = root_crt;

  while (offset < len) {
    if (ASN1_SEQUENCE != chain[offset]) {
      fprintf(stderr, "validate_cert_chain: invalid first tag\n");
      ret = -1;
      goto cleanup;
    }

    if (0 == (cert_len = get_asn1_length(chain+offset+1))) {
      fprintf(stderr, "validate_cert_chain: invalid certificate length\n");
      ret = -1;
      goto cleanup;
    }

    if (NULL == (child_crt = malloc(sizeof(mbedtls_x509_crt)))) {
      fprintf(stderr, "validate_cert_chain: failed to allocate certificate\n");
      ret = -ENOMEM;
      goto cleanup;
    }

    mbedtls_x509_crt_init(child_crt);

    // Read certificate with mbedTLS
    if (0 != (ret = mbedtls_x509_crt_parse_der_with_ext_cb(child_crt,
                        chain+offset, cert_len, 1,
                        x509_crt_ext_cb, NULL
                      ))) {
      fprintf(stderr, "validate_cert_chain: Failed to parse certificate, ret: %d\n", ret);
      return -1;
    }

    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", child_crt);
    fprintf(stderr, "%s", buf);


    if (0 != (ret =  mbedtls_x509_crt_verify(child_crt, parent_crt,
      NULL, NULL, &flags, NULL, NULL))) {
      fprintf(stderr, "validate_cert_chain: Failed to verify certificate, ret: %d\n", ret);
      return -1;
    } else {
      fprintf(stderr, "Verified certificate\n");
    }

    // Swap parent or return leaf key
    if (len > offset + cert_len) {
      // It was an intermediate certificate
      // Free the parent key, unless it is a root key
      // Replace with new key
      parent_crt = child_crt;
      // Go to next certificate in the chain
      offset += cert_len;
    } else {
      // Leaf certificate
      // return the extracted certificate
      *leaf_crt = child_crt;

      if (1 == mbedtls_pk_can_do(&(*leaf_crt)->pk, MBEDTLS_PK_ECDSA)) {
        fprintf(stderr, "Can do ECDSA\n");
      } else {
        fprintf(stderr, "Can not do ECDSA\n");
      }

      if (1 == mbedtls_pk_can_do(&(*leaf_crt)->pk, MBEDTLS_PK_ECKEY)) {
        fprintf(stderr, "Can do ECKEY\n");
      } else {
        fprintf(stderr, "Can not do ECKEY\n");
      }

      psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
      if (0 != (ret = mbedtls_pk_get_psa_attributes(&((*leaf_crt)->pk),
                  PSA_KEY_USAGE_VERIFY_MESSAGE, &attributes))) {
        fprintf(stderr, "validate_cert_chain: Failed to get PSA attributes, ret: %d\n", ret);
        return ret;
      }

      psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
      psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
      psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

      if (0 != (ret = mbedtls_pk_import_into_psa(&((*leaf_crt)->pk), &attributes, key_id))) {
        fprintf(stderr, "validate_cert_chain: Failed to import PSA key, ret: %d\n", ret);
        return ret;
      }

      psa_status_t status;
      uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
      size_t exported_length = 0;

      if (PSA_SUCCESS != (status = psa_export_public_key(*key_id, exported, sizeof(exported), &exported_length))) {
        fprintf(stderr, "PSA failed to export public key: %d\n", status);
      } else {
        fprintf(stderr, "PSA Public key: ");
        for (size_t k; k < exported_length; k++) {
          fprintf(stderr, "%02x ", exported[k]);
        }
        fprintf(stderr, "\n");
      }

      // TODO : there is certainly a memory leak. To check
      ret = 0;

      goto cleanup;
    }
  }

cleanup:

  return ret;
}

/**
 * @brief Load all root CA certificates found in a directory
 *
 * Root CA certificates must have a `.pem` extension
 *
 * Possible error codes:
 *  - EINVAL : invalid path supplied
 *  - ENOTDIR : invalid directory
 *
 * @param [in] path : path to the CA store directory
 *
 * @return 0 on SUCCESS or error code
 */
static int load_ca_store(const char *const path)
{
  DIR *d = NULL;
  struct dirent *dir;
  char *ext = NULL;

  size_t base_len = 0;
  char full_path[1024] = {0};

  if (NULL == path) {
    fprintf(stderr, "load_ca_store: invalid paramerter\n");
    return -EINVAL;
  }

  strncpy(full_path, path, 1024);
  base_len = strlen(path);

  if (NULL == (d = opendir(path))) {
    fprintf(stderr, "Failed to load CA store directory\n");
    return -ENOTDIR;
  }

  while (NULL != (dir = readdir(d))) {
    if (NULL == (ext = strrchr(dir->d_name, '.'))) {
      continue;
    }

    if (strcmp(ext, ".pem")) {
      continue;
    }

    strncpy(full_path+base_len, dir->d_name, 1024-base_len-1);

    if (0 != load_root_ca(full_path)) {
      fprintf(stderr, "Failed to read root certificate: %s\n", full_path);
    }

    memset(full_path, 0, 1024-base_len);
  }

  closedir(d);

  return 0;
}

/**
 * @brief
 *
 * @param [out] nonce : 32 byte buffer to hold nonce, caller allocated
 *
 * @return 0 on SUCCESS or an error code
 */
static int generate_nonce(uint8_t *nonce)
{
  int ret = 0;

  if (unlikely(NULL == nonce)) {
    fprintf(stderr, "generate_nonce: invalid argument\n");
    return -1;
  }

  fprintf(stderr, "generate_nonce: calling mbedtls\n");

  if (0 != (ret = mbedtls_ctr_drbg_random(&ctr_drbg, nonce, 32))) {
    fprintf(stderr, "generate_nonce: Failed to gather random, ret: %d\n", ret);
    return ret;
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// USB Policy engine functions
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Send a error message to the kernel
 *
 * @param [in] cmd    : code for the command for the initial request
 * @param [in] req_id : initial request ID
 * @param [in] error  : error code to send
 */
static void pol_eng_send_error(const enum usbauth_genl_cmds cmd, const uint32_t req_id,
                                const uint8_t error)
{
  struct nl_msg *msg = NULL;
  void *hdr = NULL;

  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_send_error: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  cmd, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_send_error: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_send_error: failed to add request ID\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, error)) {
    fprintf(stderr, "pol_eng_send_error: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_send_error: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);

  return;
}

/**
 * @brief Handle a CHECK_DIGEST request from the kernel
 *
 * The request must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ROUTE
 *  - USBAUTH_A_DIGEST
 *  - USBAUTH_A_SLOT_MASK
 *
 * The reponse must contain:
 *  - USBAUTH_A_DEV_ID
 *  - USBAUTH_A_IS_KNOWN
 *  - USBAUTH_A_IS_BLOCKED
 * or an error
 *
 * @param [in] req : pointer to the kernel request
 */
static void pol_eng_check_digest(const struct nlattr **req)
{
  uint32_t req_id = 0;
  uint8_t slot_mask = 0;
  uint8_t i = 0;
  uint8_t digests[256] = {0};
  usb_auth_dev_slot_t *slot = NULL;
  usb_auth_dev_slot_t *slots[8] = {NULL};
  uint8_t is_known = 0;
  uint8_t is_blocked = 0;
  uint32_t dev_id = 0;
  struct nl_msg *msg = NULL;
  void *hdr = NULL;

  if (unlikely(NULL == req)) {
    fprintf(stderr, "pol_eng_check_digest: invalid argument\n");
    return;
  }

  // Parse request attributes
  if (!req[USBAUTH_A_REQ_ID]) {
    // can not respond to kernel
    fprintf(stderr, "pol_eng_check_digest: invalid request: no req ID\n");
    return;
  }

  req_id = nla_get_u32(req[USBAUTH_A_REQ_ID]);
  if (!req[USBAUTH_A_DIGESTS] || !req[USBAUTH_A_SLOT_MASK] || !req[USBAUTH_A_ROUTE]) {
    fprintf(stderr, "pol_eng_check_digest: invalid request: missing arguments\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_DIGEST, req_id, USBAUTH_INVRESP);
    return;
  }

  // handle request
  dev_id = nla_get_u32(req[USBAUTH_A_ROUTE]);
  slot_mask = nla_get_u8(req[USBAUTH_A_SLOT_MASK]);
  nla_memcpy(digests, req[USBAUTH_A_DIGESTS], 256);

  pthread_mutex_lock(&usb_auth_known_slots_mut);
  for (i = 0; i < 8; i++) {
    if (1 == ((slot_mask >> i) & 1)) {
      LIST_FOREACH(slot, &usb_auth_known_slots_head, next) {
        if (!memcmp(slot->digest, digests+32*i, 32)) {
          // Digests match
          is_known |= (1 << i);
          slots[i] = slot;
          is_blocked |= (slot->blocked << i);
          break;
        }
      }
    }
  }
  pthread_mutex_unlock(&usb_auth_known_slots_mut);

  // If some slots have been found create a new device session
  if (is_known) {
    printf("pol_eng_check_digest: adding a new slot\n");
    if (0 != usb_auth_add_device(dev_id,
                                 (const usb_auth_dev_slot_t * const*) slots)) {
      fprintf(stderr, "pol_eng_check_digest: failed to add new device\n");
      pol_eng_send_error(USBAUTH_CMD_RESP_DIGEST, req_id, USBAUTH_INVRESP);
      return;
    }
  }

  // Send response
  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_check_digest: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_RESP_DIGEST, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_check_digest: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_check_digest: failed to add request ID = %i\n", req_id);
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_KNOWN, is_known)) {
    fprintf(stderr, "pol_eng_check_digest: failed to add is_known\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, USBAUTH_OK)) {
    fprintf(stderr, "pol_eng_check_digest: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_BLOCKED, is_blocked)) {
    fprintf(stderr, "pol_eng_check_digest: failed to add is_blocked\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_DEV_ID, dev_id)) {
    fprintf(stderr, "pol_eng_check_digest: failed to add device ID\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_check_digest: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);

  return;
}

/**
 * @brief Certificate chain header
 */
struct usb_auth_chain_header {
  uint16_t length; /**< Length of the certificate chain, little endian */
  uint16_t reserved; /**< Should be 0 */
  uint8_t  root_hash[32]; /**< Root certificate hash, big endian */
} __attribute__((packed));

/**
 * @brief handler for a CHECK_CERTIFICATE request
 *
 * The request must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ROUTE
 *  - USBAUTH_A_DIGEST
 *  - USBAUTH_A_CERTIFICATE
 *  - USBAUTH_A_CERT_LEN
 *
 * The response must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ERROR_CODE
 *  - USBAUTH_A_VALID
 *  - USBAUTH_A_BLOCKED
 */
static void pol_eng_check_cert(const struct nlattr **req)
{
  uint32_t req_id = 0;
  uint32_t chain_len = 0;
  uint8_t chain[4096] = {0};
  uint8_t digest[32] = {0};
  uint8_t is_valid = 0;
  uint8_t is_blocked = 0;
  uint32_t dev_id = 0;
  struct nl_msg *msg = NULL;
  void *hdr = NULL;
  struct usb_auth_chain_header *header = NULL;
  usb_auth_root_ca_t *root_ca = NULL;
  usb_auth_dev_slot_t *slot = NULL;
  usb_auth_dev_slot_t *slots[8] = {NULL};
  mbedtls_x509_crt *dev_key = NULL;
  psa_key_id_t key_id = 0;

  // Parse request attributes
  if (!req[USBAUTH_A_REQ_ID]) {
    // can not respond to kernel
    fprintf(stderr, "pol_eng_check_cert: invalid request: no req ID\n");
    return;
  }

  req_id = nla_get_u32(req[USBAUTH_A_REQ_ID]);

  if (!req[USBAUTH_A_DIGEST] || !req[USBAUTH_A_ROUTE] ||
    !req[USBAUTH_A_CERTIFICATE] || !req[USBAUTH_A_CERT_LEN]) {
    fprintf(stderr, "pol_eng_check_cert: invalid request: missing arguments\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CERTIFICATE, req_id, USBAUTH_INVRESP);
    return;
  }

  // Handle request
  chain_len = nla_get_u32(req[USBAUTH_A_CERT_LEN]);

  if (4096 < chain_len) {
    fprintf(stderr, "pol_eng_check_cert: invalid certificate chain length\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CERTIFICATE, req_id, USBAUTH_INVRESP);
    return;
  }

  nla_memcpy(chain, req[USBAUTH_A_CERTIFICATE], chain_len);

  // Check chain header to validate length, skip first 36 empty octets
  header = (struct usb_auth_chain_header *)(chain);

  if (header->length != chain_len) {
    fprintf(stderr, "pol_eng_check_cert: chain length mismatch \
header->length == %i, chain_len ==%i\n", header->length, chain_len);
    pol_eng_send_error(USBAUTH_CMD_RESP_CERTIFICATE, req_id, USBAUTH_INVRESP);
    return;
  }

  // Try to find root CA
  if (0 != usb_auth_find_root_ca(header->root_hash, &root_ca)) {
    fprintf(stderr, "pol_eng_check_cert: root ca not found\n");
    is_valid = 0;
    is_blocked = 0;
  } else {
    fprintf(stderr, "pol_eng_check_cert: found a matching root ca\n");

    if (0 != validate_cert_chain(root_ca->ctx,
                                  chain + sizeof(struct usb_auth_chain_header),
                                  header->length - sizeof(struct usb_auth_chain_header),
                                  &dev_key, &key_id)) {
      fprintf(stderr, "pol_eng_check_cert: failed to validate certificate chain\n");
      is_valid = 0;
      is_blocked = 0;
    } else {

      // Debug: print received public key
      uint8_t pub_der[1024] = {0};
      size_t pub_len = 0;
      pub_len = mbedtls_pk_write_pubkey_der(&(dev_key->pk), pub_der, 1024);

      fprintf(stderr, "Public key:\n");
      for (size_t j = 0; j < pub_len; j++) {
        fprintf(stderr, "%02x ", pub_der[j]);
      }
      fprintf(stderr, "\n");

      nla_memcpy(digest, req[USBAUTH_A_DIGEST], 32);

      // Create known certificate slot
      if (0 != usb_auth_add_slot(digest, dev_key, key_id, &slot)) {
        fprintf(stderr, "pol_eng_check_cert: failed to create new slot\n");
        pol_eng_send_error(USBAUTH_CMD_RESP_CERTIFICATE, req_id, USBAUTH_INVRESP);
        return;
      }

      // WARNING: We take two references to the same pointer. This could lead to
      // double free if not enought care is taken.
      // Create device context
      slots[0] = slot;
      dev_id = nla_get_u32(req[USBAUTH_A_ROUTE]);

      printf("pol_eng_check_cert: adding a new slot\n");
      if (0 != usb_auth_add_device(dev_id,
                                   (const usb_auth_dev_slot_t * const*) slots)) {
        fprintf(stderr, "pol_eng_check_cert: failed to add new device\n");
        pol_eng_send_error(USBAUTH_CMD_RESP_CERTIFICATE, req_id, USBAUTH_INVRESP);
        return;
      }

      is_valid = 1;
      is_blocked = 0;

    }
  }

  // Send response
  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_check_cert: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_RESP_CERTIFICATE, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_check_cert: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_check_cert: failed to add request ID\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_VALID, is_valid)) {
    fprintf(stderr, "pol_eng_check_cert: failed to add is_valid\n");
    goto cleanup;
  }

  printf("pol_eng_check_cert is equal to %i\n", USBAUTH_OK);
  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, USBAUTH_OK)) {
    fprintf(stderr, "pol_eng_check_cert: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_BLOCKED, is_blocked)) {
    fprintf(stderr, "pol_eng_check_cert: failed to add is_blocked\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_DEV_ID, dev_id)) {
    fprintf(stderr, "pol_eng_check_cert: failed to add device ID\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_check_cert: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);
}

/**
 * @brief handler for a REMOVE_DEV request
 *
 * The request must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_DEV_ID
 *
 * The response must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ERROR_CODE
 */
static void pol_eng_remove_dev(const struct nlattr **req)
{
  uint32_t req_id = 0;
  uint32_t dev_id = 0;
  struct nl_msg *msg = NULL;
  void *hdr = NULL;

  // Parse request attributes
  if (!req[USBAUTH_A_REQ_ID]) {
    // can not respond to kernel
    fprintf(stderr, "pol_eng_remove_dev: invalid request: no req ID\n");
    return;
  }

  req_id = nla_get_u32(req[USBAUTH_A_REQ_ID]);

  if (!req[USBAUTH_A_DEV_ID]) {
    fprintf(stderr, "pol_eng_remove_dev: invalid request: missing arguments\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_REMOVE_DEV, req_id, USBAUTH_INVRESP);
    return;
  }

  // Handle request
  dev_id = nla_get_u32(req[USBAUTH_A_DEV_ID]);

  // Try to find device and remove it
  if (0 != usb_auth_remove_device(dev_id)) {
    fprintf(stderr, "pol_eng_remove_dev: failed to remove device\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_REMOVE_DEV, req_id, USBAUTH_INVRESP);
    return;
  }

  // Send response
  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_remove_dev: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_RESP_REMOVE_DEV, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_remove_dev: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_remove_dev: failed to add request ID\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, USBAUTH_OK)) {
    fprintf(stderr, "pol_eng_remove_dev: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_remove_dev: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);
}

/**
 * @brief handler for a GENERATE_CHALLENGE request
 *
 * The request must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_DEV_ID
 *
 * The response must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ERROR_CODE
 *  - USBAUTH_A_NONCE
 */
static void pol_eng_generate_chall(const struct nlattr **req)
{
  uint32_t req_id = 0;
  uint32_t dev_id = 0;
  uint8_t nonce[32] = {0};
  usb_auth_device_t *dev = NULL;
  struct nl_msg *msg = NULL;
  void *hdr = NULL;

  // Parse request attributes
  if (!req[USBAUTH_A_REQ_ID]) {
    // can not respond to kernel
    fprintf(stderr, "pol_eng_generate_chall: invalid request: no req ID\n");
    return;
  }

  req_id = nla_get_u32(req[USBAUTH_A_REQ_ID]);

  if (!req[USBAUTH_A_DEV_ID]) {
    fprintf(stderr, "pol_eng_generate_chall: invalid request: missing arguments\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_GEN_NONCE, req_id, USBAUTH_INVRESP);
    return;
  }

  // Handle request
  dev_id = nla_get_u32(req[USBAUTH_A_DEV_ID]);

  if (0 != usb_auth_get_device(dev_id, &dev)) {
    fprintf(stderr, "pol_eng_generate_chall: device not found\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_GEN_NONCE, req_id, USBAUTH_INVRESP);
    return;
  }

  if (0 != generate_nonce(nonce)) {
    fprintf(stderr, "pol_eng_generate_chall: failed to generate the nonce");
    pol_eng_send_error(USBAUTH_CMD_RESP_GEN_NONCE, req_id, USBAUTH_INVRESP);
    return;
  }

  // Register nonce
  memcpy(dev->nonce, nonce, 32);

  // Send response
  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_generate_chall: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_RESP_GEN_NONCE, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_generate_chall: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_generate_chall: failed to add request ID\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, USBAUTH_OK)) {
    fprintf(stderr, "pol_eng_generate_chall: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nla_put(msg, USBAUTH_A_NONCE, 32, nonce)) {
    fprintf(stderr, "pol_eng_generate_chall: failed to add nonce\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_generate_chall: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);
}

/**
 * @brief handler for a CHECK_CHALLENGE request
 *
 * The request must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_DEV_ID
 *  - USBAUTH_A_CHALL
 *  - USBAUTH_A_DESCRIPTOR
 *
 * The response must contain:
 *  - USBAUTH_A_REQ_ID
 *  - USBAUTH_A_ERROR_CODE
 *  - USBAUTH_A_VALID
 */
static void pol_eng_check_chall(const struct nlattr **req)
{
  uint32_t req_id = 0;
  uint32_t dev_id = 0;
  uint8_t i = 0;
  uint8_t is_valid = 0;
  uint8_t chall[204] = {0};
  uint8_t desc[512] = {0};
  int desc_size = 0;
  uint8_t hash[32] = {0};
  struct nl_msg *msg = NULL;
  void *hdr = NULL;
  usb_auth_device_t *dev = NULL;
  psa_status_t status;
  psa_hash_operation_t sha256 = PSA_HASH_OPERATION_INIT;
  size_t hash_len = 0;

  // Parse request attributes
  if (!req[USBAUTH_A_REQ_ID]) {
    // can not respond to kernel
    fprintf(stderr, "pol_eng_check_chall: invalid request: no req ID\n");
    return;
  }

  req_id = nla_get_u32(req[USBAUTH_A_REQ_ID]);

  if (!req[USBAUTH_A_DEV_ID] || !req[USBAUTH_A_CHALL] ||
      !req[USBAUTH_A_DESCRIPTOR]) {
    fprintf(stderr, "pol_eng_check_chall: invalid request: missing arguments\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CHECK_CHALL, req_id, USBAUTH_INVRESP);
    return;
  }

  // Handle request
  dev_id = nla_get_u32(req[USBAUTH_A_DEV_ID]);
  nla_memcpy(chall, req[USBAUTH_A_CHALL], 204);

  if (0 != usb_auth_get_device(dev_id, &dev)) {
    fprintf(stderr, "pol_eng_check_chall: device not found\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CHECK_CHALL, req_id, USBAUTH_INVRESP);
    return;
  }

  // Check that the nonce signed is the one we generated for the session
  if (memcmp(dev->nonce, chall+4, 32)) {
    fprintf(stderr, "pol_eng_check_chall: invalid challenge nonce\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CHECK_CHALL, req_id, USBAUTH_INVRESP);
    return;
  }

  // Get the certificate to use to verify the challenge
  for (i = 0; i < 8; i++) {
    if (dev && dev->slots[i]) {

      if (!memcmp(chall+44, dev->slots[i]->digest, 32)) {
        break;
      }
    }
  }

  if (8 == i) {
    fprintf(stderr, "pol_eng_check_chall: certificate not found\n");
    pol_eng_send_error(USBAUTH_CMD_RESP_CHECK_CHALL, req_id, USBAUTH_INVRESP);
    return;
  }

  // Get device context
  desc_size = nla_len(req[USBAUTH_A_DESCRIPTOR]);
  nla_memcpy(desc, req[USBAUTH_A_DESCRIPTOR], desc_size);

  fprintf(stderr, "Challenge: ");
  for (int i = 0; i < 140; i++) {
    fprintf(stderr, "%02x ", chall[i]);
  }
  fprintf(stderr, "\n");

  fprintf(stderr, "Signature: ");
  for (int i = 0; i < 64; i++) {
    fprintf(stderr, "%02x ", chall[140+i]);
  }
  fprintf(stderr, "\n");

  fprintf(stderr, "Descriptor %d: \n", desc_size);
  for (int i = 0; i < desc_size; i++) {
    fprintf(stderr, "%02x ", desc[i]);
  }
  fprintf(stderr, "\n");

  // Verify device descriptor
  if (PSA_SUCCESS != (status = psa_hash_setup(&sha256, PSA_ALG_SHA_256))) {
    fprintf(stderr, "pol_eng_check_chall: failed init sha\n");
    return;
  }

  if (PSA_SUCCESS != (status = psa_hash_update(&sha256, desc, desc_size))) {
    fprintf(stderr, "pol_eng_check_chall: failed to update sha\n");
    return;
  }

  if (PSA_SUCCESS != (status = psa_hash_finish(&sha256, hash, 32, &hash_len))) {
    fprintf(stderr, "pol_eng_check_chall: failed to finalize sha\n");
    return;
  }

  if (32 != hash_len) {
    fprintf(stderr, "pol_eng_check_chall: invalid hash length\n");
    return;
  }

  if (memcmp(hash, chall + 108, 32)) {
    fprintf(stderr, "pol_eng_check_chall: failed to validate device context hash\n");
    is_valid = 0;
  } else {
    // Verify challenge
    if (PSA_SUCCESS != (status = psa_verify_message(
                          dev->slots[i]->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                          chall, 140,
                          chall+140, 64
      ))) {
      fprintf(stderr, "pol_eng_check_chall: PSA failed to verify: %d\n", status);
      is_valid = 0;
    } else {
      fprintf(stderr, "pol_eng_check_chall: PSA verified message successfuly\n");
      is_valid = 1;
    }
  }

  // Send response
  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "pol_eng_check_chall: failed to allocate message\n");
    return;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_RESP_CHECK_CHALL, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "pol_eng_check_chall: failed to create header\n");
    goto cleanup;
  }

  if (0 > nla_put_u32(msg, USBAUTH_A_REQ_ID, req_id)) {
    fprintf(stderr, "pol_eng_check_chall: failed to add request ID\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_ERROR_CODE, USBAUTH_OK)) {
    fprintf(stderr, "pol_eng_check_chall: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nla_put_u8(msg, USBAUTH_A_VALID, is_valid)) {
    fprintf(stderr, "pol_eng_check_chall: failed to add error code\n");
    goto cleanup;
  }

  if (0 > nl_send_auto(ucsk, msg)) {
    fprintf(stderr, "pol_eng_check_chall: failed to send message\n");
    goto cleanup;
  }

cleanup:
  nlmsg_free(msg);
}

////////////////////////////////////////////////////////////////////////////////
// USB policy engine netlink socket management
////////////////////////////////////////////////////////////////////////////////

static int krn_req_handler(struct nl_msg *msg, void *arg)
{
  int err = 0;
  struct genlmsghdr *genlhdr = NULL;
  struct nlattr *tb[USBAUTH_A_MAX+1];

  (void) arg;

  fprintf(stderr, "krn_req_handler: message received\n");

  if (NULL == (genlhdr = nlmsg_data(nlmsg_hdr(msg)))) {
    fprintf(stderr, "krn_req_handler: failed to get message header\n");
    return NL_SKIP;
  }

  if (0 != (err = nla_parse(tb, USBAUTH_A_MAX, genlmsg_attrdata(genlhdr, 0),
                            genlmsg_attrlen(genlhdr, 0), NULL))) {
    fprintf(stderr, "krn_req_handler: unable to parse message: %s\n", strerror(-err));
    return NL_SKIP;
  }

  switch (genlhdr->cmd) {
    case USBAUTH_CMD_REGISTER:
      return NL_SKIP;
    case USBAUTH_CMD_CHECK_DIGEST:
      fprintf(stderr, "krn_req_handler: received check digest command\n");
      pol_eng_check_digest((const struct nlattr **) tb);
      return NL_OK;

    case USBAUTH_CMD_CHECK_CERTIFICATE:
      fprintf(stderr, "krn_req_handler: received check certificate command\n");
      pol_eng_check_cert((const struct nlattr **) tb);
      return NL_OK;

    case USBAUTH_CMD_REMOVE_DEV:
      fprintf(stderr, "krn_req_handler: received remove device command\n");
      pol_eng_remove_dev((const struct nlattr **) tb);
      return NL_OK;

    case USBAUTH_CMD_GEN_NONCE:
      fprintf(stderr, "krn_req_handler: received generate nonce command\n");
      pol_eng_generate_chall((const struct nlattr **) tb);
      return NL_OK;

    case USBAUTH_CMD_CHECK_CHALL:
      fprintf(stderr, "krn_req_handler: received check challenge command\n");
      pol_eng_check_chall((const struct nlattr **) tb);
      return NL_OK;

    default:
      fprintf(stderr, "krn_req_handler: invalid command: %d\n", genlhdr->cmd);
      return NL_STOP;
  }
}

static int krn_register(int fam)
{
  int ret = 0;
  struct nl_msg *msg = NULL;
  void *hdr = NULL;

  if (NULL == (msg = nlmsg_alloc())) {
    fprintf(stderr, "krn_register: failed to allocate message\n");
    return -ENOMEM;
  }

  if (NULL == (hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fam, 0, 0,
                                  USBAUTH_CMD_REGISTER, USBAUTH_GENL_VERSION))) {
    fprintf(stderr, "krn_register: failed to create header\n");
    return -EMSGSIZE;
  }

  ret = nl_send_auto(ucsk, msg);
  ret = ret >= 0 ? 0 : ret;

  fprintf(stderr, "krn_register: message sent\n");

  nlmsg_free(msg);

  return ret;
}

static int conn(struct nl_sock **sk)
{
  *sk = nl_socket_alloc();
  if (NULL == sk) {
    return -ENOMEM;
  }

  return genl_connect(*sk);
}

static void disconn(struct nl_sock *sk)
{
  nl_close(sk);
  nl_socket_free(sk);
}

static inline int set_cb(struct nl_sock *sk)
{
  nl_socket_disable_seq_check(sk);
  return nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
                              krn_req_handler, NULL);
}


////////////////////////////////////////////////////////////////////////////////
// Policy Engine entry point
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
  int ret = 1;
  psa_status_t status;
  mbedtls_entropy_context entropy;

  // Check inputs
  if (argc != 3) {
    fprintf(stderr, "Invalid number of arguments, use -root_store path\n");
    return -1;
  }

  if (!strcmp(argv[1], "-root_store")) {
    fprintf(stderr, "Invalid number of arguments, use -root_store path\n");
    return -1;
  }

  #if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODE_OWNER)
  fprintf(stderr, "Mbedtls PSA crypto not supported\n");
  #endif

  if (PSA_SUCCESS != (status = psa_crypto_init())) {
    fprintf(stderr, "Failed to initialize PSA crypto\n");
  }

  // Initialize entropy
  mbedtls_entropy_init( &entropy );

  char *personalization = "usb_policy_engine";
  mbedtls_ctr_drbg_init( &ctr_drbg );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                   (const unsigned char *) personalization,
                    strlen( personalization ) );
  if( ret != 0 )
  {
    fprintf(stderr, "Failed to initialize random generator, ret: %d\n", ret);
  }

  LIST_INIT(&usb_auth_known_slots_head);
  LIST_INIT(&usb_auth_root_store_head);
  LIST_INIT(&usb_auth_devs_head);

  if (0 != load_ca_store(argv[2])) {
    fprintf(stderr, "Failed to load CA store\n");
    return -1;
  }

  if ((ret = conn(&ucsk))) {
    fprintf(stderr, "Failed to connect to generic netlink\n");
    goto out;
  }

  if (NULL == ucsk) {
    fprintf(stderr, "Failed to create socket\n");
    goto out;
  }

  if (0 > (fam = genl_ctrl_resolve(ucsk, USBAUTH_GENL_NAME))) {
    fprintf(stderr, "Failed to resolve family: %s\n", strerror(-fam));
    goto out;
  }

  if ((ret = set_cb(ucsk))) {
    fprintf(stderr, "Failed to set callback: %s\n", strerror(-ret));
    goto out;
  }

  // Register policy engine in the USB stack
  if ((ret = krn_register(fam))) {
    fprintf(stderr, "Failed to register policy handler: %s\n", strerror(-ret));
    goto out;
  }

  while (1) {
    fd_set rfds;
    int fd, retval;

    fd = nl_socket_get_fd(ucsk);

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    /* wait for an incoming message on the netlink socket */
    retval = select(fd+1, &rfds, NULL, NULL, NULL);

    if (retval) {
      nl_recvmsgs_default(ucsk);
    }
  }

  ret = 0;

out:
  disconn(ucsk);

  usb_auth_free_root_list();

  return ret;
}
