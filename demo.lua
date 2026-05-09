package.cpath = "./?.so;" .. package.cpath

local oqs = require("oqs")

local function to_hex(bytes)
  local parts = {}

  for i = 1, #bytes do
    parts[i] = string.format("%02x", string.byte(bytes, i))
  end

  return table.concat(parts)
end

local function assert_equal(left, right, message)
  assert(left == right, message)
end

local keypair = oqs.keypair()

print("algorithm:", oqs.algorithm())
print("public_key:", #keypair.public_key)
print("secret_key:", #keypair.secret_key)

local encapsulated = oqs.encaps(keypair.public_key)
local receiver_shared_secret = oqs.decaps(
  encapsulated.ciphertext,
  keypair.secret_key
)

assert_equal(
  encapsulated.shared_secret,
  receiver_shared_secret,
  "shared secret mismatch"
)

print("ciphertext_kem:", #encapsulated.ciphertext)
print("shared_secret_match:", encapsulated.shared_secret == receiver_shared_secret)

local sender_aes_key = oqs.derive_aes_key(encapsulated.shared_secret)
local receiver_aes_key = oqs.derive_aes_key(receiver_shared_secret)

assert_equal(sender_aes_key, receiver_aes_key, "AES key mismatch")

print("aes_key_match:", sender_aes_key == receiver_aes_key)

local payload = [[{"customerId":"cust_123","amount":149.90,"currency":"USD","issuedAt":"2026-05-09T22:15:59.013Z","note":"Payment approved via hybrid PQC + AES channel"}]]

local encrypted = oqs.encrypt(payload, sender_aes_key)
local decrypted = oqs.decrypt(
  encrypted.ciphertext,
  receiver_aes_key,
  encrypted.iv,
  encrypted.auth_tag
)

assert_equal(decrypted, payload, "decrypted payload mismatch")

print("payload_original:", payload)
print("iv:", to_hex(encrypted.iv))
print("auth_tag:", to_hex(encrypted.auth_tag))
print("ciphertext:", to_hex(encrypted.ciphertext))
print("payload_decrypted:", decrypted)
