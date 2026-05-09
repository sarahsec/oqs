#include <lauxlib.h>
#include <lua.h>

#include <oqs/oqs.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OQS_LUA_KEM OQS_KEM_alg_ml_kem_768
#define OQS_LUA_SIG OQS_SIG_alg_ml_dsa_65
#define OQS_LUA_AES_KEY_LEN 32
#define OQS_LUA_AES_GCM_IV_LEN 12
#define OQS_LUA_AES_GCM_TAG_LEN 16

static int openssl_error(lua_State *L, const char *message) {
  char buffer[256];
  unsigned long err = ERR_get_error();

  if (err == 0) {
    return luaL_error(L, "%s", message);
  }

  ERR_error_string_n(err, buffer, sizeof(buffer));
  return luaL_error(L, "%s: %s", message, buffer);
}

static int errno_error(lua_State *L, const char *message) {
  return luaL_error(L, "%s: %s", message, strerror(errno));
}

static void secure_cleanse(void *ptr, size_t len) {
  if (ptr != NULL && len > 0) {
    OPENSSL_cleanse(ptr, len);
  }
}

static void secure_free(void *ptr, size_t len) {
  if (ptr != NULL) {
    secure_cleanse(ptr, len);
    free(ptr);
  }
}

static void set_binary_field(
  lua_State *L,
  const char *key,
  const unsigned char *value,
  size_t value_len
) {
  lua_pushlstring(L, (const char *) value, value_len);
  lua_setfield(L, -2, key);
}

static OQS_KEM *new_kem(lua_State *L) {
  OQS_KEM *kem = OQS_KEM_new(OQS_LUA_KEM);

  if (kem == NULL) {
    luaL_error(L, "failed to initialize ML-KEM-768");
  }

  return kem;
}

static OQS_SIG *new_sig(lua_State *L) {
  OQS_SIG *sig = OQS_SIG_new(OQS_LUA_SIG);

  if (sig == NULL) {
    luaL_error(L, "failed to initialize ML-DSA-65");
  }

  return sig;
}

static int l_kem_keypair(lua_State *L) {
  OQS_KEM *kem = new_kem(L);
  unsigned char *public_key = malloc(kem->length_public_key);
  unsigned char *secret_key = malloc(kem->length_secret_key);

  if (public_key == NULL || secret_key == NULL) {
    OQS_KEM_free(kem);
    free(public_key);
    secure_free(secret_key, kem->length_secret_key);
    return luaL_error(L, "failed to allocate KEM key buffers");
  }

  if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    free(public_key);
    secure_free(secret_key, kem->length_secret_key);
    return luaL_error(L, "KEM keypair failed");
  }

  lua_createtable(L, 0, 2);
  set_binary_field(L, "public_key", public_key, kem->length_public_key);
  set_binary_field(L, "secret_key", secret_key, kem->length_secret_key);

  OQS_KEM_free(kem);
  free(public_key);
  secure_free(secret_key, kem->length_secret_key);

  return 1;
}

static int l_sig_keypair(lua_State *L) {
  OQS_SIG *sig = new_sig(L);
  unsigned char *public_key = malloc(sig->length_public_key);
  unsigned char *secret_key = malloc(sig->length_secret_key);

  if (public_key == NULL || secret_key == NULL) {
    OQS_SIG_free(sig);
    free(public_key);
    secure_free(secret_key, sig->length_secret_key);
    return luaL_error(L, "failed to allocate signature key buffers");
  }

  if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
    OQS_SIG_free(sig);
    free(public_key);
    secure_free(secret_key, sig->length_secret_key);
    return luaL_error(L, "signature keypair failed");
  }

  lua_createtable(L, 0, 2);
  set_binary_field(L, "public_key", public_key, sig->length_public_key);
  set_binary_field(L, "secret_key", secret_key, sig->length_secret_key);

  OQS_SIG_free(sig);
  free(public_key);
  secure_free(secret_key, sig->length_secret_key);

  return 1;
}

static int l_encaps(lua_State *L) {
  size_t public_key_len = 0;
  const unsigned char *public_key =
    (const unsigned char *) luaL_checklstring(L, 1, &public_key_len);

  OQS_KEM *kem = new_kem(L);

  if (public_key_len != kem->length_public_key) {
    OQS_KEM_free(kem);
    return luaL_error(
      L,
      "invalid KEM public key length: expected %zu, got %zu",
      kem->length_public_key,
      public_key_len
    );
  }

  unsigned char *ciphertext = malloc(kem->length_ciphertext);
  unsigned char *shared_secret = malloc(kem->length_shared_secret);

  if (ciphertext == NULL || shared_secret == NULL) {
    OQS_KEM_free(kem);
    free(ciphertext);
    secure_free(shared_secret, kem->length_shared_secret);
    return luaL_error(L, "failed to allocate encapsulation buffers");
  }

  if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    free(ciphertext);
    secure_free(shared_secret, kem->length_shared_secret);
    return luaL_error(L, "encapsulation failed");
  }

  lua_createtable(L, 0, 2);
  set_binary_field(L, "ciphertext", ciphertext, kem->length_ciphertext);
  set_binary_field(L, "shared_secret", shared_secret, kem->length_shared_secret);

  OQS_KEM_free(kem);
  free(ciphertext);
  secure_free(shared_secret, kem->length_shared_secret);

  return 1;
}

static int l_decaps(lua_State *L) {
  size_t ciphertext_len = 0;
  size_t secret_key_len = 0;
  const unsigned char *ciphertext =
    (const unsigned char *) luaL_checklstring(L, 1, &ciphertext_len);
  const unsigned char *secret_key =
    (const unsigned char *) luaL_checklstring(L, 2, &secret_key_len);

  OQS_KEM *kem = new_kem(L);

  if (ciphertext_len != kem->length_ciphertext) {
    OQS_KEM_free(kem);
    return luaL_error(
      L,
      "invalid KEM ciphertext length: expected %zu, got %zu",
      kem->length_ciphertext,
      ciphertext_len
    );
  }

  if (secret_key_len != kem->length_secret_key) {
    OQS_KEM_free(kem);
    return luaL_error(
      L,
      "invalid KEM secret key length: expected %zu, got %zu",
      kem->length_secret_key,
      secret_key_len
    );
  }

  unsigned char *shared_secret = malloc(kem->length_shared_secret);

  if (shared_secret == NULL) {
    OQS_KEM_free(kem);
    return luaL_error(L, "failed to allocate decapsulation buffer");
  }

  if (OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    secure_free(shared_secret, kem->length_shared_secret);
    return luaL_error(L, "decapsulation failed");
  }

  lua_pushlstring(
    L,
    (const char *) shared_secret,
    kem->length_shared_secret
  );

  OQS_KEM_free(kem);
  secure_free(shared_secret, kem->length_shared_secret);

  return 1;
}

static int l_derive_aes_key(lua_State *L) {
  size_t shared_secret_len = 0;
  size_t info_len = 0;
  const unsigned char *shared_secret =
    (const unsigned char *) luaL_checklstring(L, 1, &shared_secret_len);
  const unsigned char *info =
    (const unsigned char *) luaL_optlstring(
      L,
      2,
      "oqs-lua aes-256-gcm key",
      &info_len
    );

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  unsigned char key[OQS_LUA_AES_KEY_LEN];
  size_t key_len = sizeof(key);

  if (ctx == NULL) {
    return openssl_error(L, "failed to create HKDF context");
  }

  if (
    EVP_PKEY_derive_init(ctx) <= 0 ||
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char *) "", 0) <= 0 ||
    EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, shared_secret_len) <= 0 ||
    EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0 ||
    EVP_PKEY_derive(ctx, key, &key_len) <= 0
  ) {
    EVP_PKEY_CTX_free(ctx);
    secure_cleanse(key, sizeof(key));
    return openssl_error(L, "HKDF failed");
  }

  EVP_PKEY_CTX_free(ctx);
  lua_pushlstring(L, (const char *) key, key_len);
  secure_cleanse(key, sizeof(key));
  return 1;
}

static int l_encrypt(lua_State *L) {
  size_t plaintext_len = 0;
  size_t key_len = 0;
  size_t iv_len = 0;
  const unsigned char *plaintext =
    (const unsigned char *) luaL_checklstring(L, 1, &plaintext_len);
  const unsigned char *key =
    (const unsigned char *) luaL_checklstring(L, 2, &key_len);
  const unsigned char *iv_input = NULL;
  unsigned char iv[OQS_LUA_AES_GCM_IV_LEN];
  unsigned char auth_tag[OQS_LUA_AES_GCM_TAG_LEN];
  unsigned char *ciphertext = NULL;
  int out_len = 0;
  int final_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;

  if (key_len != OQS_LUA_AES_KEY_LEN) {
    return luaL_error(
      L,
      "invalid AES key length: expected %d, got %zu",
      OQS_LUA_AES_KEY_LEN,
      key_len
    );
  }

  if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
    iv_input = (const unsigned char *) luaL_checklstring(L, 3, &iv_len);

    if (iv_len != OQS_LUA_AES_GCM_IV_LEN) {
      return luaL_error(
        L,
        "invalid AES-GCM IV length: expected %d, got %zu",
        OQS_LUA_AES_GCM_IV_LEN,
        iv_len
      );
    }

    memcpy(iv, iv_input, sizeof(iv));
  } else {
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
      return openssl_error(L, "failed to generate IV");
    }
  }

  ciphertext = malloc(plaintext_len + OQS_LUA_AES_GCM_TAG_LEN);

  if (ciphertext == NULL) {
    return luaL_error(L, "failed to allocate ciphertext buffer");
  }

  ctx = EVP_CIPHER_CTX_new();

  if (ctx == NULL) {
    free(ciphertext);
    return openssl_error(L, "failed to create cipher context");
  }

  if (
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len) != 1 ||
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1 ||
    EVP_CIPHER_CTX_ctrl(
      ctx,
      EVP_CTRL_GCM_GET_TAG,
      sizeof(auth_tag),
      auth_tag
    ) != 1
  ) {
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    secure_cleanse(iv, sizeof(iv));
    secure_cleanse(auth_tag, sizeof(auth_tag));
    return openssl_error(L, "AES-256-GCM encryption failed");
  }

  lua_createtable(L, 0, 3);
  set_binary_field(L, "iv", iv, sizeof(iv));
  set_binary_field(L, "ciphertext", ciphertext, (size_t) (out_len + final_len));
  set_binary_field(L, "auth_tag", auth_tag, sizeof(auth_tag));

  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);
  secure_cleanse(iv, sizeof(iv));
  secure_cleanse(auth_tag, sizeof(auth_tag));

  return 1;
}

static int l_decrypt(lua_State *L) {
  size_t ciphertext_len = 0;
  size_t key_len = 0;
  size_t iv_len = 0;
  size_t auth_tag_len = 0;
  const unsigned char *ciphertext =
    (const unsigned char *) luaL_checklstring(L, 1, &ciphertext_len);
  const unsigned char *key =
    (const unsigned char *) luaL_checklstring(L, 2, &key_len);
  const unsigned char *iv =
    (const unsigned char *) luaL_checklstring(L, 3, &iv_len);
  const unsigned char *auth_tag =
    (const unsigned char *) luaL_checklstring(L, 4, &auth_tag_len);
  unsigned char *plaintext = NULL;
  int out_len = 0;
  int final_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;

  if (key_len != OQS_LUA_AES_KEY_LEN) {
    return luaL_error(
      L,
      "invalid AES key length: expected %d, got %zu",
      OQS_LUA_AES_KEY_LEN,
      key_len
    );
  }

  if (iv_len != OQS_LUA_AES_GCM_IV_LEN) {
    return luaL_error(
      L,
      "invalid AES-GCM IV length: expected %d, got %zu",
      OQS_LUA_AES_GCM_IV_LEN,
      iv_len
    );
  }

  if (auth_tag_len != OQS_LUA_AES_GCM_TAG_LEN) {
    return luaL_error(
      L,
      "invalid AES-GCM auth tag length: expected %d, got %zu",
      OQS_LUA_AES_GCM_TAG_LEN,
      auth_tag_len
    );
  }

  plaintext = malloc(ciphertext_len + 1);

  if (plaintext == NULL) {
    return luaL_error(L, "failed to allocate plaintext buffer");
  }

  ctx = EVP_CIPHER_CTX_new();

  if (ctx == NULL) {
    free(plaintext);
    return openssl_error(L, "failed to create cipher context");
  }

  if (
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1 ||
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
    EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len) != 1 ||
    EVP_CIPHER_CTX_ctrl(
      ctx,
      EVP_CTRL_GCM_SET_TAG,
      auth_tag_len,
      (void *) auth_tag
    ) != 1
  ) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return openssl_error(L, "AES-256-GCM decryption setup failed");
  }

  if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return luaL_error(L, "AES-256-GCM authentication failed");
  }

  lua_pushlstring(L, (const char *) plaintext, (size_t) (out_len + final_len));

  EVP_CIPHER_CTX_free(ctx);
  free(plaintext);

  return 1;
}

static int l_sign(lua_State *L) {
  size_t message_len = 0;
  size_t secret_key_len = 0;
  const unsigned char *message =
    (const unsigned char *) luaL_checklstring(L, 1, &message_len);
  const unsigned char *secret_key =
    (const unsigned char *) luaL_checklstring(L, 2, &secret_key_len);
  OQS_SIG *sig = new_sig(L);
  unsigned char *signature = NULL;
  size_t signature_len = sig->length_signature;

  if (secret_key_len != sig->length_secret_key) {
    OQS_SIG_free(sig);
    return luaL_error(
      L,
      "invalid signature secret key length: expected %zu, got %zu",
      sig->length_secret_key,
      secret_key_len
    );
  }

  signature = malloc(sig->length_signature);

  if (signature == NULL) {
    OQS_SIG_free(sig);
    return luaL_error(L, "failed to allocate signature buffer");
  }

  if (
    OQS_SIG_sign(
      sig,
      signature,
      &signature_len,
      message,
      message_len,
      secret_key
    ) != OQS_SUCCESS
  ) {
    OQS_SIG_free(sig);
    free(signature);
    return luaL_error(L, "signing failed");
  }

  lua_pushlstring(L, (const char *) signature, signature_len);

  OQS_SIG_free(sig);
  free(signature);

  return 1;
}

static int l_verify(lua_State *L) {
  size_t message_len = 0;
  size_t signature_len = 0;
  size_t public_key_len = 0;
  const unsigned char *message =
    (const unsigned char *) luaL_checklstring(L, 1, &message_len);
  const unsigned char *signature =
    (const unsigned char *) luaL_checklstring(L, 2, &signature_len);
  const unsigned char *public_key =
    (const unsigned char *) luaL_checklstring(L, 3, &public_key_len);
  OQS_SIG *sig = new_sig(L);
  OQS_STATUS status = OQS_ERROR;

  if (public_key_len != sig->length_public_key) {
    OQS_SIG_free(sig);
    return luaL_error(
      L,
      "invalid signature public key length: expected %zu, got %zu",
      sig->length_public_key,
      public_key_len
    );
  }

  status = OQS_SIG_verify(
    sig,
    message,
    message_len,
    signature,
    signature_len,
    public_key
  );

  OQS_SIG_free(sig);
  lua_pushboolean(L, status == OQS_SUCCESS);
  return 1;
}

static int l_write_file(lua_State *L) {
  const char *path = luaL_checkstring(L, 1);
  size_t data_len = 0;
  const char *data = luaL_checklstring(L, 2, &data_len);
  int private_file = lua_toboolean(L, 3);
  int overwrite = lua_toboolean(L, 4);
  mode_t mode =
    private_file
      ? (S_IRUSR | S_IWUSR)
      : (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  int flags = O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL);
  int fd = open(path, flags, mode);
  size_t written_total = 0;

  if (fd < 0) {
    return errno_error(L, "failed to open output file");
  }

  while (written_total < data_len) {
    ssize_t written = write(fd, data + written_total, data_len - written_total);

    if (written < 0) {
      close(fd);
      return errno_error(L, "failed to write output file");
    }

    written_total += (size_t) written;
  }

  if (close(fd) != 0) {
    return errno_error(L, "failed to close output file");
  }

  lua_pushboolean(L, 1);
  return 1;
}

static int l_kem_algorithm(lua_State *L) {
  lua_pushstring(L, OQS_LUA_KEM);
  return 1;
}

static int l_sig_algorithm(lua_State *L) {
  lua_pushstring(L, OQS_LUA_SIG);
  return 1;
}

static const luaL_Reg oqs_lib[] = {
  {"algorithm", l_kem_algorithm},
  {"keypair", l_kem_keypair},
  {"kem_algorithm", l_kem_algorithm},
  {"sig_algorithm", l_sig_algorithm},
  {"kem_keypair", l_kem_keypair},
  {"sig_keypair", l_sig_keypair},
  {"encaps", l_encaps},
  {"decaps", l_decaps},
  {"derive_aes_key", l_derive_aes_key},
  {"encrypt", l_encrypt},
  {"decrypt", l_decrypt},
  {"sign", l_sign},
  {"verify", l_verify},
  {"write_file", l_write_file},
  {NULL, NULL}
};

int luaopen_oqs(lua_State *L) {
  luaL_newlib(L, oqs_lib);
  return 1;
}
