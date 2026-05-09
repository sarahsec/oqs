package.cpath = "./?.so;" .. package.cpath

local oqs = require("oqs")

local MAGIC_ENC = "OQS1"
local MAGIC_SIG = "OQSS"
local MAGIC_SEL = "OQSL"
local VERSION   = 0x0001
local IV_LEN    = 12
local TAG_LEN   = 16

local ok_count   = 0
local fail_count = 0

local function proved(label)
  ok_count = ok_count + 1
  io.write(string.format("  PROVED  %s\n", label))
end

local function failed(label, reason)
  fail_count = fail_count + 1
  io.write(string.format("  FAILED  %s: %s\n", label, tostring(reason)))
end

local function section(title)
  io.write(string.format("\n==> %s\n", title))
end

local function looks_like_plaintext(bytes, needle)
  return bytes:find(needle, 1, true) ~= nil
end

local function encode_enc(kem_ct, iv, auth_tag, aes_ct)
  return MAGIC_ENC
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #kem_ct)
    .. kem_ct .. iv .. auth_tag .. aes_ct
end

local function decode_enc(blob)
  local kem_ct_len = string.unpack(">I4", blob, 7)
  local cur    = 11
  local kem_ct = blob:sub(cur, cur + kem_ct_len - 1); cur = cur + kem_ct_len
  local iv     = blob:sub(cur, cur + IV_LEN - 1);     cur = cur + IV_LEN
  local tag    = blob:sub(cur, cur + TAG_LEN - 1);    cur = cur + TAG_LEN
  return kem_ct, iv, tag, blob:sub(cur)
end

local function encode_sig(sig)
  return MAGIC_SIG
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #sig)
    .. sig
end

local function decode_sig(blob)
  local sig_len = string.unpack(">I4", blob, 7)
  return blob:sub(11, 10 + sig_len)
end

local plaintext = "TOP SECRET: transfer $1,000,000 to account 987654321"

section("Confidentiality — ciphertext reveals nothing about plaintext")
do
  local kem  = oqs.kem_keypair()
  local enc  = oqs.encaps(kem.public_key)
  local key  = oqs.derive_aes_key(enc.shared_secret)
  local aes  = oqs.encrypt(plaintext, key)
  local blob = encode_enc(enc.ciphertext, aes.iv, aes.auth_tag, aes.ciphertext)

  if not looks_like_plaintext(blob, "SECRET") then
    proved("ciphertext does not contain the word SECRET")
  else
    failed("ciphertext does not contain the word SECRET", "plaintext leaked")
  end

  if not looks_like_plaintext(blob, "1,000,000") then
    proved("ciphertext does not contain the dollar amount")
  else
    failed("ciphertext does not contain the dollar amount", "plaintext leaked")
  end

  if #blob > #plaintext then
    proved(string.format("blob is larger than plaintext (%d > %d bytes — KEM overhead)", #blob, #plaintext))
  else
    failed("blob size check", "blob is suspiciously small")
  end
end

section("Integrity — tampered ciphertext is always rejected")
do
  local kem  = oqs.kem_keypair()
  local enc  = oqs.encaps(kem.public_key)
  local key  = oqs.derive_aes_key(enc.shared_secret)
  local aes  = oqs.encrypt(plaintext, key)
  local blob = encode_enc(enc.ciphertext, aes.iv, aes.auth_tag, aes.ciphertext)

  local shared = oqs.decaps(enc.ciphertext, kem.secret_key)
  local dec_key = oqs.derive_aes_key(shared)

  local variants = {
    { "last 4 bytes flipped",  blob:sub(1, #blob - 4) .. "\x00\x00\x00\x00" },
    { "first payload byte XORed", blob:sub(1, 11 + #enc.ciphertext + IV_LEN + TAG_LEN) .. string.char(blob:byte(11 + #enc.ciphertext + IV_LEN + TAG_LEN + 1) ~ 0xFF) .. blob:sub(11 + #enc.ciphertext + IV_LEN + TAG_LEN + 2) },
    { "auth tag zeroed",       blob:sub(1, 11 + #enc.ciphertext + IV_LEN - 1) .. string.rep("\x00", TAG_LEN) .. blob:sub(11 + #enc.ciphertext + IV_LEN + TAG_LEN) },
  }

  for _, v in ipairs(variants) do
    local label, tampered = v[1], v[2]
    local kem_ct, iv, tag, aes_ct = decode_enc(tampered)
    local ok = pcall(oqs.decrypt, aes_ct, dec_key, iv, tag)
    if not ok then
      proved("rejected: " .. label)
    else
      failed("rejected: " .. label, "decryption succeeded on tampered data")
    end
  end
end

section("Key isolation — wrong private key cannot decrypt")
do
  local alice = oqs.kem_keypair()
  local bob   = oqs.kem_keypair()

  local enc    = oqs.encaps(alice.public_key)
  local key    = oqs.derive_aes_key(enc.shared_secret)
  local aes    = oqs.encrypt(plaintext, key)
  local blob   = encode_enc(enc.ciphertext, aes.iv, aes.auth_tag, aes.ciphertext)

  local kem_ct, iv, tag, aes_ct = decode_enc(blob)

  local bob_shared = oqs.decaps(kem_ct, bob.secret_key)
  local bob_key    = oqs.derive_aes_key(bob_shared)

  local ok, result = pcall(oqs.decrypt, aes_ct, bob_key, iv, tag)
  if not ok then
    proved("Bob's key cannot decrypt Alice's ciphertext (AES-GCM auth fail)")
  elseif result == plaintext then
    failed("key isolation", "Bob decrypted Alice's message — catastrophic")
  else
    proved("Bob's key produced garbage, not the original plaintext")
  end
end

section("Authenticity — ML-DSA-65 signature binds message to key")
do
  local sig_pair  = oqs.sig_keypair()
  local message   = "Authorized: release funds to account 987654321"
  local signature = oqs.sign(message, sig_pair.secret_key)
  local blob      = encode_sig(signature)

  local valid = oqs.verify(message, decode_sig(blob), sig_pair.public_key)
  if valid then
    proved("original message verifies correctly")
  else
    failed("original message verifies correctly", "valid sig rejected")
  end

  local tampered_msg = "Authorized: release funds to account 000000000"
  local invalid = oqs.verify(tampered_msg, decode_sig(blob), sig_pair.public_key)
  if not invalid then
    proved("tampered message rejected (account number changed)")
  else
    failed("tampered message rejected", "forgery accepted")
  end

  local other = oqs.sig_keypair()
  local wrong_key = oqs.verify(message, decode_sig(blob), other.public_key)
  if not wrong_key then
    proved("correct message rejected under a different public key")
  else
    failed("wrong public key check", "foreign key accepted the signature")
  end
end

section("Seal/Open — sign-then-encrypt provides confidentiality + authenticity atomically")
do
  local kem_pair  = oqs.kem_keypair()
  local sig_pair  = oqs.sig_keypair()
  local message   = "Wire $500,000 to account 111222333 — authorized by CEO"

  local function seal(sig_secret, kem_public, pt)
    local signature = oqs.sign(pt, sig_secret)
    local inner     = string.pack(">I4", #signature) .. signature .. pt
    local encaps    = oqs.encaps(kem_public)
    local aes_key   = oqs.derive_aes_key(encaps.shared_secret)
    local encrypted = oqs.encrypt(inner, aes_key)
    local kem_ct    = encaps.ciphertext
    return MAGIC_SEL
      .. string.pack(">I2", VERSION)
      .. string.pack(">I4", #kem_ct)
      .. kem_ct
      .. encrypted.iv
      .. encrypted.auth_tag
      .. encrypted.ciphertext
  end

  local function open(kem_secret, sig_public, blob)
    local kem_ct_len = string.unpack(">I4", blob, 7)
    local cur = 11
    local kem_ct = blob:sub(cur, cur + kem_ct_len - 1); cur = cur + kem_ct_len
    local iv     = blob:sub(cur, cur + IV_LEN - 1);     cur = cur + IV_LEN
    local tag    = blob:sub(cur, cur + TAG_LEN - 1);    cur = cur + TAG_LEN
    local aes_ct = blob:sub(cur)
    local shared  = oqs.decaps(kem_ct, kem_secret)
    local aes_key = oqs.derive_aes_key(shared)
    local inner   = oqs.decrypt(aes_ct, aes_key, iv, tag)
    local sig_len   = string.unpack(">I4", inner, 1)
    local signature = inner:sub(5, 4 + sig_len)
    local pt        = inner:sub(5 + sig_len)
    if not oqs.verify(pt, signature, sig_public) then
      error("signature verification failed")
    end
    return pt
  end

  local blob = seal(sig_pair.secret_key, kem_pair.public_key, message)

  if not looks_like_plaintext(blob, "500,000") then
    proved("sealed blob does not expose the dollar amount")
  else
    failed("sealed blob does not expose the dollar amount", "plaintext leaked")
  end

  if not looks_like_plaintext(blob, "CEO") then
    proved("sealed blob does not expose the word CEO")
  else
    failed("sealed blob does not expose the word CEO", "plaintext leaked")
  end

  local recovered = open(kem_pair.secret_key, sig_pair.public_key, blob)
  if recovered == message then
    proved("open recovers original message intact")
  else
    failed("open recovers original message intact", "content mismatch")
  end

  local attacker_kem = oqs.kem_keypair()
  local ok_wrong_kem = pcall(open, attacker_kem.secret_key, sig_pair.public_key, blob)
  if not ok_wrong_kem then
    proved("attacker without recipient key cannot open")
  else
    failed("attacker without recipient key cannot open", "decryption succeeded")
  end

  local forger_sig = oqs.sig_keypair()
  local ok_wrong_sig = pcall(open, kem_pair.secret_key, forger_sig.public_key, blob)
  if not ok_wrong_sig then
    proved("wrong sender public key is rejected — identity forgery impossible")
  else
    failed("wrong sender public key rejected", "forgery accepted")
  end

  local tampered = blob:sub(1, #blob - 4) .. "\x00\x00\x00\x00"
  local ok_tamper = pcall(open, kem_pair.secret_key, sig_pair.public_key, tampered)
  if not ok_tamper then
    proved("tampered sealed blob is rejected before plaintext is exposed")
  else
    failed("tampered sealed blob rejected", "tampered data accepted")
  end
end

section("Key-type enforcement — KEM keys cannot be used for signing")
do
  local kem = oqs.kem_keypair()

  local ok = pcall(oqs.sign, plaintext, kem.secret_key)
  if not ok then
    proved("oqs.sign rejects a KEM secret key (wrong key length)")
  else
    failed("key-type enforcement", "sign accepted a KEM key")
  end
end

io.write(string.format(
  "\n%d proved, %d failed\n\n",
  ok_count, fail_count
))

if fail_count > 0 then os.exit(1) end
