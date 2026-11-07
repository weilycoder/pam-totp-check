#define _GNU_SOURCE
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define TOTP_PERIOD 30
#define TOTP_DIGITS 6
#define WINDOW 1

static int base32_decode(const char *in, unsigned char *out, size_t outlen) {
  static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  size_t bits = 0, idx = 0;
  uint32_t buffer = 0;
  for (const char *p = in; *p; p++) {
    if (*p == '=' || *p == ' ' || *p == '\n')
      continue;
    char ch = *p;
    if (ch >= 'a' && ch <= 'z')
      ch -= 'a' - 'A';
    const char *q = strchr(alphabet, ch);
    if (!q)
      return -1;
    buffer = (buffer << 5) | (q - alphabet);
    bits += 5;
    if (bits >= 8) {
      if (idx >= outlen)
        return -1;
      out[idx++] = (buffer >> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return (int)idx;
}

static uint32_t totp_at(const unsigned char *key, size_t keylen,
                        uint64_t counter) {
  unsigned char msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = counter & 0xFF;
    counter >>= 8;
  }
  unsigned char hmac[20];
  unsigned int hlen = 0;
  HMAC(EVP_sha1(), key, (int)keylen, msg, 8, hmac, &hlen);

  int offset = hmac[19] & 0x0F;
  uint32_t bin = ((hmac[offset] & 0x7F) << 24) | (hmac[offset + 1] << 16) |
                 (hmac[offset + 2] << 8) | (hmac[offset + 3]);
  return bin % 1000000;
}

static int ct_equal_str(const char *a, const char *b) {
  if (strlen(a) != strlen(b))
    return 0;
  unsigned char r = 0;
  for (size_t i = 0; a[i]; i++)
    r |= a[i] ^ b[i];
  return r == 0;
}

static int is_totp_code(const char *code) {
  if (!code || strlen(code) != TOTP_DIGITS)
    return 0;
  for (size_t i = 0; i < TOTP_DIGITS; i++) {
    if (code[i] < '0' || code[i] > '9')
      return 0;
  }
  return 1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  (void)flags;
  const char *secret_b32 = NULL;
  char secret_buf[128] = {0};

  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "secret=", 7) == 0) {
      secret_b32 = argv[i] + 7;
    } else if (strncmp(argv[i], "secret_file=", 12) == 0) {
      FILE *f = fopen(argv[i] + 12, "r");
      if (!f) {
        return PAM_IGNORE;
      }
      if (!fgets(secret_buf, sizeof secret_buf, f)) {
        fclose(f);
        return PAM_IGNORE;
      }
      if (!feof(f) && !strchr(secret_buf, '\n')) {
        fclose(f);
        return PAM_IGNORE;
      }
      if (ferror(f)) {
        fclose(f);
        return PAM_IGNORE;
      }
      fclose(f);
      secret_buf[strcspn(secret_buf, "\r\n")] = 0;
      secret_b32 = secret_buf;
    }
  }
  if (!secret_b32) {
    return PAM_IGNORE;
  }

  const char *code = NULL;
  pam_get_item(pamh, PAM_AUTHTOK, (const void **)&code);
  if (!code) {
    int rc = pam_get_authtok(pamh, PAM_AUTHTOK, &code, NULL);
    if (rc != PAM_SUCCESS || !code)
      return PAM_IGNORE;
  }
  if (!is_totp_code(code))
    return PAM_IGNORE;

  unsigned char key[64];
  int keylen = base32_decode(secret_b32, key, sizeof key);
  if (keylen <= 0) {
    return PAM_IGNORE;
  }

  uint64_t now = (uint64_t)time(NULL);
  uint64_t counter = now / TOTP_PERIOD;

  for (int w = -WINDOW; w <= WINDOW; w++) {
    if (w < 0 && counter < (uint64_t)-w)
      continue;
    uint64_t candidate = w < 0 ? counter - (uint64_t)-w : counter + (uint64_t)w;
    uint32_t expect = totp_at(key, keylen, candidate);
    char expect_str[TOTP_DIGITS + 1];
    snprintf(expect_str, sizeof expect_str, "%0*u", TOTP_DIGITS, expect);
    if (ct_equal_str(code, expect_str)) {
      const char *user = NULL;
      pam_get_user(pamh, &user, NULL);
      return PAM_SUCCESS;
    }
  }

  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}