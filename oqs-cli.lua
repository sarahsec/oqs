package.cpath = "./?.so;" .. package.cpath

local oqs = require("oqs")

local MAGIC_ENC = "OQS1"
local MAGIC_SIG = "OQSS"
local MAGIC_SEL = "OQSL"
local MAGIC_PUB = "OQKP"
local MAGIC_SEC = "OQKS"
local VERSION   = 0x0001

local IV_LEN       = 12
local AUTH_TAG_LEN = 16

local function die(msg)
  io.stderr:write("error: " .. msg .. "\n")
  os.exit(1)
end

local function info(msg)
  io.stdout:write(msg .. "\n")
end

local function read_file(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, "cannot open '" .. path .. "': " .. err
  end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, data, is_private)
  local ok, err = pcall(oqs.write_file, path, data, is_private or false, false)
  if not ok then
    if type(err) == "string" and err:find("File exists") then
      return nil, "'" .. path .. "' already exists — remove it first"
    end
    return nil, tostring(err)
  end
  return true
end

local function must_read(path)
  local data, err = read_file(path)
  if not data then die(err) end
  return data
end

local function must_write(path, data, is_private)
  local ok, err = write_file(path, data, is_private)
  if not ok then die(err) end
end

local function encode_key(magic, ktype, key_bytes)
  return magic .. string.pack(">I2", VERSION) .. ktype .. key_bytes
end

local function decode_key(path, expected_magic, expected_type)
  local data = must_read(path)

  if #data < 4 + 2 + 3 + 1 then
    die("key file '" .. path .. "' is too short or corrupted")
  end

  local magic   = data:sub(1, 4)
  local version = string.unpack(">I2", data, 5)
  local ktype   = data:sub(7, 9)
  local key     = data:sub(10)

  if magic ~= expected_magic then
    die("'" .. path .. "': wrong file type (got '" .. magic ..
        "', expected '" .. expected_magic .. "')")
  end
  if version ~= VERSION then
    die("'" .. path .. "': unsupported version " .. version)
  end
  if ktype ~= expected_type then
    die("'" .. path .. "': wrong algorithm type (expected '" ..
        expected_type .. "', got '" .. ktype .. "')")
  end

  return key
end

local function cmd_keygen(args)
  local ktype = args[1]
  local name  = args[2]

  if ktype ~= "kem" and ktype ~= "sig" then
    die("keygen: type must be 'kem' or 'sig'")
  end
  if not name or name == "" then
    die("keygen: output key name is required")
  end

  local pair, algo
  if ktype == "kem" then
    pair = oqs.kem_keypair()
    algo = oqs.kem_algorithm()
  else
    pair = oqs.sig_keypair()
    algo = oqs.sig_algorithm()
  end

  local pub_path  = name .. ".pub"
  local priv_path = name .. ".priv"

  must_write(pub_path,  encode_key(MAGIC_PUB, ktype, pair.public_key), false)
  must_write(priv_path, encode_key(MAGIC_SEC, ktype, pair.secret_key), true)

  info("algorithm  : " .. algo)
  info("public key : " .. pub_path)
  info("private key: " .. priv_path .. "  [mode 0600]")
end

local function cmd_encrypt(args)
  local pub_path = args[1]
  local in_path  = args[2]
  local out_path = args[3]

  if not pub_path or not in_path or not out_path then
    die("usage: encrypt <pubkey.pub> <input> <output>")
  end

  local pub_key   = decode_key(pub_path, MAGIC_PUB, "kem")
  local plaintext = must_read(in_path)

  local encaps    = oqs.encaps(pub_key)
  local aes_key   = oqs.derive_aes_key(encaps.shared_secret)
  local encrypted = oqs.encrypt(plaintext, aes_key)

  local kem_ct = encaps.ciphertext
  local blob = MAGIC_ENC
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #kem_ct)
    .. kem_ct
    .. encrypted.iv
    .. encrypted.auth_tag
    .. encrypted.ciphertext

  must_write(out_path, blob, false)

  info("encrypted  : " .. in_path .. " -> " .. out_path)
  info("kem        : " .. oqs.kem_algorithm())
  info("sym        : AES-256-GCM")
end

local function cmd_decrypt(args)
  local priv_path = args[1]
  local in_path   = args[2]
  local out_path  = args[3]

  if not priv_path or not in_path or not out_path then
    die("usage: decrypt <privkey.priv> <input> <output>")
  end

  local secret_key = decode_key(priv_path, MAGIC_SEC, "kem")
  local blob       = must_read(in_path)

  if #blob < 4 + 2 + 4 then
    die("'" .. in_path .. "' is too short to be a valid encrypted file")
  end

  local magic = blob:sub(1, 4)
  if magic ~= MAGIC_ENC then
    die("'" .. in_path .. "' is not a valid OQS encrypted file")
  end

  local version = string.unpack(">I2", blob, 5)
  if version ~= VERSION then
    die("unsupported encrypted-file version " .. version)
  end

  local kem_ct_len = string.unpack(">I4", blob, 7)
  local cursor     = 11

  local kem_ct = blob:sub(cursor, cursor + kem_ct_len - 1)
  cursor = cursor + kem_ct_len

  if #kem_ct ~= kem_ct_len then
    die("truncated KEM ciphertext in '" .. in_path .. "'")
  end

  local iv = blob:sub(cursor, cursor + IV_LEN - 1)
  cursor = cursor + IV_LEN

  local auth_tag = blob:sub(cursor, cursor + AUTH_TAG_LEN - 1)
  cursor = cursor + AUTH_TAG_LEN

  local aes_ct = blob:sub(cursor)

  if #iv ~= IV_LEN then
    die("corrupted IV in '" .. in_path .. "'")
  end
  if #auth_tag ~= AUTH_TAG_LEN then
    die("corrupted auth tag in '" .. in_path .. "'")
  end

  local shared_secret = oqs.decaps(kem_ct, secret_key)
  local aes_key       = oqs.derive_aes_key(shared_secret)

  local ok, result = pcall(oqs.decrypt, aes_ct, aes_key, iv, auth_tag)
  if not ok then
    die("decryption failed — wrong key or file is corrupted / tampered")
  end

  must_write(out_path, result, false)
  info("decrypted  : " .. in_path .. " -> " .. out_path)
end

local function cmd_sign(args)
  local priv_path = args[1]
  local in_path   = args[2]
  local out_path  = args[3]

  if not priv_path or not in_path or not out_path then
    die("usage: sign <privkey.priv> <input> <output.sig>")
  end

  local secret_key = decode_key(priv_path, MAGIC_SEC, "sig")
  local message    = must_read(in_path)
  local signature  = oqs.sign(message, secret_key)

  local blob = MAGIC_SIG
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #signature)
    .. signature

  must_write(out_path, blob, false)

  info("signed     : " .. in_path .. " -> " .. out_path)
  info("algorithm  : " .. oqs.sig_algorithm())
end

local function cmd_verify(args)
  local pub_path = args[1]
  local in_path  = args[2]
  local sig_path = args[3]

  if not pub_path or not in_path or not sig_path then
    die("usage: verify <pubkey.pub> <input> <signature.sig>")
  end

  local public_key = decode_key(pub_path, MAGIC_PUB, "sig")
  local message    = must_read(in_path)
  local sig_blob   = must_read(sig_path)

  if #sig_blob < 4 + 2 + 4 then
    die("signature file '" .. sig_path .. "' is too short or corrupted")
  end

  local magic = sig_blob:sub(1, 4)
  if magic ~= MAGIC_SIG then
    die("'" .. sig_path .. "' is not a valid OQS signature file")
  end

  local version = string.unpack(">I2", sig_blob, 5)
  if version ~= VERSION then
    die("unsupported signature-file version " .. version)
  end

  local sig_len   = string.unpack(">I4", sig_blob, 7)
  local signature = sig_blob:sub(11, 10 + sig_len)

  if #signature ~= sig_len then
    die("truncated signature in '" .. sig_path .. "'")
  end

  local valid = oqs.verify(message, signature, public_key)

  if valid then
    info("OK  signature valid: " .. in_path .. " verified with " .. sig_path)
  else
    io.stderr:write("FAIL  SIGNATURE INVALID: " .. in_path .. "\n")
    os.exit(1)
  end
end

local function cmd_seal(args)
  local sig_priv_path = args[1]
  local kem_pub_path  = args[2]
  local in_path       = args[3]
  local out_path      = args[4]

  if not sig_priv_path or not kem_pub_path or not in_path or not out_path then
    die("usage: seal <sender.priv> <recipient.pub> <input> <output>")
  end

  local sig_key   = decode_key(sig_priv_path, MAGIC_SEC, "sig")
  local kem_key   = decode_key(kem_pub_path,  MAGIC_PUB, "kem")
  local plaintext = must_read(in_path)

  local signature = oqs.sign(plaintext, sig_key)
  local inner     = string.pack(">I4", #signature) .. signature .. plaintext

  local encaps    = oqs.encaps(kem_key)
  local aes_key   = oqs.derive_aes_key(encaps.shared_secret)
  local encrypted = oqs.encrypt(inner, aes_key)

  local kem_ct = encaps.ciphertext
  local blob = MAGIC_SEL
    .. string.pack(">I2", VERSION)
    .. string.pack(">I4", #kem_ct)
    .. kem_ct
    .. encrypted.iv
    .. encrypted.auth_tag
    .. encrypted.ciphertext

  must_write(out_path, blob, false)

  info("sealed     : " .. in_path .. " -> " .. out_path)
  info("kem        : " .. oqs.kem_algorithm())
  info("sig        : " .. oqs.sig_algorithm())
  info("sym        : AES-256-GCM")
end

local function cmd_open(args)
  local kem_priv_path = args[1]
  local sig_pub_path  = args[2]
  local in_path       = args[3]
  local out_path      = args[4]

  if not kem_priv_path or not sig_pub_path or not in_path or not out_path then
    die("usage: open <recipient.priv> <sender.pub> <input> <output>")
  end

  local kem_key = decode_key(kem_priv_path, MAGIC_SEC, "kem")
  local sig_key = decode_key(sig_pub_path,  MAGIC_PUB, "sig")
  local blob    = must_read(in_path)

  if #blob < 4 + 2 + 4 then
    die("'" .. in_path .. "' is too short to be a valid sealed file")
  end

  local magic = blob:sub(1, 4)
  if magic ~= MAGIC_SEL then
    die("'" .. in_path .. "' is not a valid OQS sealed file")
  end

  local version = string.unpack(">I2", blob, 5)
  if version ~= VERSION then
    die("unsupported sealed-file version " .. version)
  end

  local kem_ct_len = string.unpack(">I4", blob, 7)
  local cursor     = 11

  local kem_ct = blob:sub(cursor, cursor + kem_ct_len - 1)
  cursor = cursor + kem_ct_len

  if #kem_ct ~= kem_ct_len then
    die("truncated KEM ciphertext in '" .. in_path .. "'")
  end

  local iv = blob:sub(cursor, cursor + IV_LEN - 1)
  cursor = cursor + IV_LEN

  local auth_tag = blob:sub(cursor, cursor + AUTH_TAG_LEN - 1)
  cursor = cursor + AUTH_TAG_LEN

  local aes_ct = blob:sub(cursor)

  if #iv ~= IV_LEN then
    die("corrupted IV in '" .. in_path .. "'")
  end
  if #auth_tag ~= AUTH_TAG_LEN then
    die("corrupted auth tag in '" .. in_path .. "'")
  end

  local shared_secret = oqs.decaps(kem_ct, kem_key)
  local aes_key       = oqs.derive_aes_key(shared_secret)

  local ok, inner = pcall(oqs.decrypt, aes_ct, aes_key, iv, auth_tag)
  if not ok then
    die("decryption failed — wrong recipient key or file is corrupted / tampered")
  end

  if #inner < 4 then
    die("sealed payload is malformed")
  end

  local sig_len   = string.unpack(">I4", inner, 1)
  local signature = inner:sub(5, 4 + sig_len)
  local plaintext = inner:sub(5 + sig_len)

  if #signature ~= sig_len then
    die("malformed signature inside sealed payload")
  end

  if not oqs.verify(plaintext, signature, sig_key) then
    die("signature verification failed — sender identity could not be confirmed")
  end

  must_write(out_path, plaintext, false)

  info("opened     : " .. in_path .. " -> " .. out_path)
  info("decrypted  : OK")
  info("verified   : OK  (" .. oqs.sig_algorithm() .. ")")
end

local function usage()
  io.stderr:write(string.format([[
oqs-cli  post-quantum file encryption and signing

USAGE:
  oqs-cli keygen  <kem|sig>      <name>
  oqs-cli encrypt <pubkey.pub>   <input>           <output>
  oqs-cli decrypt <privkey.priv> <input>           <output>
  oqs-cli sign    <privkey.priv> <input>           <output.sig>
  oqs-cli verify  <pubkey.pub>   <input>           <signature.sig>
  oqs-cli seal    <sender.priv>  <recipient.pub>   <input>   <output>
  oqs-cli open    <recipient.priv> <sender.pub>    <input>   <output>

ALGORITHMS:
  KEM : %s
  SIG : %s
  SYM : AES-256-GCM
  KDF : HKDF-SHA256

EXAMPLES:
  # Encrypt + sign atomically (seal/open):
  oqs-cli keygen  kem alice
  oqs-cli keygen  sig bob
  oqs-cli seal    bob.priv    alice.pub    secret.txt   secret.sealed
  oqs-cli open    alice.priv  bob.pub      secret.sealed secret.txt

  # Encrypt only:
  oqs-cli encrypt alice.pub    secret.txt   secret.enc
  oqs-cli decrypt alice.priv   secret.enc   secret.txt

  # Sign only:
  oqs-cli sign    bob.priv     report.pdf   report.pdf.sig
  oqs-cli verify  bob.pub      report.pdf   report.pdf.sig

]], oqs.kem_algorithm(), oqs.sig_algorithm()))
  os.exit(1)
end

local commands = {
  keygen  = cmd_keygen,
  encrypt = cmd_encrypt,
  decrypt = cmd_decrypt,
  sign    = cmd_sign,
  verify  = cmd_verify,
  seal    = cmd_seal,
  open    = cmd_open,
}

local cmd_name = arg and arg[1]
if not cmd_name or not commands[cmd_name] then
  usage()
end

local sub_args = {}
for i = 2, #arg do
  sub_args[i - 1] = arg[i]
end

local ok, err = pcall(commands[cmd_name], sub_args)
if not ok then
  die(tostring(err))
end
