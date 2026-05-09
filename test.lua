package.cpath = "./?.so;" .. package.cpath

local oqs = require("oqs")

local passed = 0
local failed = 0

local function pass(name)
  passed = passed + 1
  io.write("  PASS  " .. name .. "\n")
end

local function fail(name, reason)
  failed = failed + 1
  io.write("  FAIL  " .. name .. ": " .. tostring(reason) .. "\n")
end

local function check(name, ok, reason)
  if ok then pass(name) else fail(name, reason or "assertion failed") end
end

local function must(expr, msg)
  if not expr then
    error(msg or "assertion failed", 2)
  end
  return expr
end

local temp_files = {}

local function tmpfile()
  local path = os.tmpname()
  temp_files[#temp_files + 1] = path
  return path
end

local function read_file(path)
  local f, err = io.open(path, "rb")
  if not f then return nil, err end
  local d = f:read("*a")
  f:close()
  return d
end

local function write_oqs(path, data, is_private)
  os.remove(path)
  local ok, err = pcall(oqs.write_file, path, data, is_private or false, true)
  if not ok then error(err) end
end

local MAGIC_ENC = "OQS1"
local MAGIC_SIG = "OQSS"
local MAGIC_SEL = "OQSL"
local MAGIC_PUB = "OQKP"
local MAGIC_SEC = "OQKS"
local VERSION   = 0x0001
local IV_LEN    = 12
local TAG_LEN   = 16

local function encode_key(magic, ktype, key_bytes)
  return magic .. string.pack(">I2", VERSION) .. ktype .. key_bytes
end

local function decode_key(data, expected_magic, expected_type)
  must(#data >= 4 + 2 + 3 + 1, "key blob too short")
  local magic   = data:sub(1, 4)
  local version = string.unpack(">I2", data, 5)
  local ktype   = data:sub(7, 9)
  local key     = data:sub(10)
  must(magic == expected_magic,   "wrong magic: " .. magic)
  must(version == VERSION,        "wrong version: " .. version)
  must(ktype == expected_type,    "wrong type: " .. ktype)
  return key
end

local function encode_enc(kem_ct, iv, auth_tag, aes_ct)
  return MAGIC_ENC
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #kem_ct)
    .. kem_ct .. iv .. auth_tag .. aes_ct
end

local function decode_enc(blob)
  must(#blob >= 4 + 2 + 4, "enc blob too short")
  must(blob:sub(1, 4) == MAGIC_ENC, "wrong ENC magic")
  must(string.unpack(">I2", blob, 5) == VERSION, "wrong ENC version")
  local kem_ct_len = string.unpack(">I4", blob, 7)
  local cur = 11
  local kem_ct = blob:sub(cur, cur + kem_ct_len - 1)
  cur = cur + kem_ct_len
  local iv       = blob:sub(cur, cur + IV_LEN - 1);  cur = cur + IV_LEN
  local auth_tag = blob:sub(cur, cur + TAG_LEN - 1); cur = cur + TAG_LEN
  local aes_ct   = blob:sub(cur)
  must(#kem_ct   == kem_ct_len, "truncated KEM ciphertext")
  must(#iv       == IV_LEN,     "truncated IV")
  must(#auth_tag == TAG_LEN,    "truncated auth tag")
  return kem_ct, iv, auth_tag, aes_ct
end

local function encode_sig(signature)
  return MAGIC_SIG
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #signature)
    .. signature
end

local function decode_sig(blob)
  must(#blob >= 4 + 2 + 4, "sig blob too short")
  must(blob:sub(1, 4) == MAGIC_SIG, "wrong SIG magic")
  must(string.unpack(">I2", blob, 5) == VERSION, "wrong SIG version")
  local sig_len   = string.unpack(">I4", blob, 7)
  local signature = blob:sub(11, 10 + sig_len)
  must(#signature == sig_len, "truncated signature")
  return signature
end

io.write("\n==> keygen kem\n")
do
  local pair = oqs.kem_keypair()
  check("kem public key non-empty",  #pair.public_key > 0)
  check("kem secret key non-empty",  #pair.secret_key > 0)

  local pub_blob  = encode_key(MAGIC_PUB, "kem", pair.public_key)
  local priv_blob = encode_key(MAGIC_SEC, "kem", pair.secret_key)

  local pub_path  = tmpfile()
  local priv_path = tmpfile()
  write_oqs(pub_path,  pub_blob, false)
  write_oqs(priv_path, priv_blob, true)

  local pub_data  = assert(read_file(pub_path))
  local priv_data = assert(read_file(priv_path))

  local pub_key  = decode_key(pub_data,  MAGIC_PUB, "kem")
  local priv_key = decode_key(priv_data, MAGIC_SEC, "kem")

  check("kem public key round-trips",  pub_key  == pair.public_key)
  check("kem secret key round-trips",  priv_key == pair.secret_key)
end

io.write("\n==> keygen sig\n")
do
  local pair = oqs.sig_keypair()
  check("sig public key non-empty",  #pair.public_key > 0)
  check("sig secret key non-empty",  #pair.secret_key > 0)

  local pub_blob  = encode_key(MAGIC_PUB, "sig", pair.public_key)
  local priv_blob = encode_key(MAGIC_SEC, "sig", pair.secret_key)

  local pub_key  = decode_key(pub_blob,  MAGIC_PUB, "sig")
  local priv_key = decode_key(priv_blob, MAGIC_SEC, "sig")

  check("sig public key round-trips",  pub_key  == pair.public_key)
  check("sig secret key round-trips",  priv_key == pair.secret_key)
end

io.write("\n==> encrypt / decrypt\n")
do
  local kem_pair  = oqs.kem_keypair()
  local plaintext = "Segredo pós-quântico: " .. os.time()

  local encaps    = oqs.encaps(kem_pair.public_key)
  local aes_key   = oqs.derive_aes_key(encaps.shared_secret)
  local encrypted = oqs.encrypt(plaintext, aes_key)

  local blob = encode_enc(
    encaps.ciphertext,
    encrypted.iv,
    encrypted.auth_tag,
    encrypted.ciphertext
  )

  check("encrypted blob has ENC magic", blob:sub(1, 4) == MAGIC_ENC)

  local kem_ct, iv, auth_tag, aes_ct = decode_enc(blob)
  local shared  = oqs.decaps(kem_ct, kem_pair.secret_key)
  local dec_key = oqs.derive_aes_key(shared)
  local result  = oqs.decrypt(aes_ct, dec_key, iv, auth_tag)

  check("decrypt produces original plaintext", result == plaintext)

  local tampered_blob = blob:sub(1, #blob - 4) .. "\x00\x00\x00\x00"
  local t_kem_ct, t_iv, t_auth_tag, t_aes_ct = decode_enc(tampered_blob)
  local t_shared  = oqs.decaps(t_kem_ct, kem_pair.secret_key)
  local t_dec_key = oqs.derive_aes_key(t_shared)
  local ok_tamper = pcall(oqs.decrypt, t_aes_ct, t_dec_key, t_iv, t_auth_tag)
  check("tampered ciphertext is rejected by AES-GCM", not ok_tamper)
end

io.write("\n==> sign / verify\n")
do
  local sig_pair = oqs.sig_keypair()
  local message  = "Mensagem autêntica pós-quântica."

  local signature = oqs.sign(message, sig_pair.secret_key)
  local blob      = encode_sig(signature)

  check("signature blob has SIG magic", blob:sub(1, 4) == MAGIC_SIG)

  local decoded_sig = decode_sig(blob)
  local valid       = oqs.verify(message, decoded_sig, sig_pair.public_key)
  check("valid signature is accepted",  valid == true)

  local invalid = oqs.verify("tampered message", decoded_sig, sig_pair.public_key)
  check("tampered message is rejected", invalid == false)
end

io.write("\n==> key-type cross-use rejection\n")
do
  local kem_pair  = oqs.kem_keypair()
  local priv_blob = encode_key(MAGIC_SEC, "kem", kem_pair.secret_key)

  local ok = pcall(decode_key, priv_blob, MAGIC_SEC, "sig")
  check("KEM secret key rejected when SIG type expected", not ok)

  local pub_blob = encode_key(MAGIC_PUB, "kem", kem_pair.public_key)
  local ok2 = pcall(decode_key, pub_blob, MAGIC_SEC, "kem")
  check("public key rejected when secret key expected",  not ok2)
end

io.write("\n==> wrong-magic rejection\n")
do
  local garbage = "XXXX\x00\x01kemABCDEFGH"
  local ok = pcall(decode_key, garbage, MAGIC_PUB, "kem")
  check("wrong magic rejected", not ok)
end

io.write("\n==> seal / open\n")
do
  local kem_pair = oqs.kem_keypair()
  local sig_pair = oqs.sig_keypair()
  local plaintext = "Sealed post-quantum message: " .. os.time()

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
    must(blob:sub(1, 4) == MAGIC_SEL, "wrong magic")
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
    must(oqs.verify(pt, signature, sig_public), "signature verification failed")
    return pt
  end

  local blob = seal(sig_pair.secret_key, kem_pair.public_key, plaintext)
  check("sealed blob has OQSL magic", blob:sub(1, 4) == MAGIC_SEL)

  local result = open(kem_pair.secret_key, sig_pair.public_key, blob)
  check("open recovers original plaintext", result == plaintext)

  local other_kem = oqs.kem_keypair()
  local ok_wrong_kem = pcall(open, other_kem.secret_key, sig_pair.public_key, blob)
  check("wrong recipient key is rejected", not ok_wrong_kem)

  local other_sig = oqs.sig_keypair()
  local ok_wrong_sig = pcall(open, kem_pair.secret_key, other_sig.public_key, blob)
  check("wrong sender key is rejected", not ok_wrong_sig)

  local tampered = blob:sub(1, #blob - 4) .. "\x00\x00\x00\x00"
  local ok_tamper = pcall(open, kem_pair.secret_key, sig_pair.public_key, tampered)
  check("tampered sealed file is rejected", not ok_tamper)
end

for _, p in ipairs(temp_files) do os.remove(p) end

io.write(string.format("\n%d passed, %d failed\n\n", passed, failed))

if failed > 0 then os.exit(1) end
