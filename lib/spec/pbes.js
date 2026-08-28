import asn1 from "asn1.js";
import * as dstszi2010 from "./dstszi2010.js";
import * as rfc3280 from "./rfc3280.js";

const CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier;
const ContentInfo = dstszi2010.ContentInfo;
const MAX_PBES2_SALT_LENGTH = 1024;
const MAX_KDF_ITERATIONS = 100000;

// Reference: https://www.rfc-editor.org/rfc/rfc2898

var OID = {
  "1 2 840 113549 1 5 13": "PBES2",
  "1 2 840 113549 1 5 12": "PBKDF2",
  "1 2 804 2 1 1 1 1 2 2 4": "Dstu7564mac-256",
  "1 2 804 2 1 1 1 1 1 3 5 2": "Dstu7624cbc-256"
};

var Dstu7624Parameters = asn1.define("Dstu7624Parameters", function() {
  this.seq().obj(this.key("iv").octstr());
});

var PBKDF2_params = asn1.define("PBKDF2-params", function() {
  this.seq().obj(
    this.key("salt").octstr(),
    this.key("cycles").int(),
    this.key("keyLength")
      .optional()
      .int(),
    this.key("hash").use(CipherParams)
  );
});

var PBES2_params = asn1.define("PBES2-params", function() {
  this.seq().obj(
    this.key("keyDerivationFunc")
      .seq()
      .obj(this.key("id").objid(OID), this.key("params").use(PBKDF2_params)),
    this.key("encryptionScheme").use(CipherParams)
  );
});

var PBES2Algorithms = asn1.define("PBES2Algorithms", function() {
  this.seq().obj(
    this.key("algorithm").objid(OID),
    this.key("parameters").choice({
      null_: this.null_(),
      params: this.use(PBES2_params)
    })
  );
});

var PBES2 = asn1.define("StorePBES2", function() {
  this.seq().obj(
    this.key("contentEncryptionAlgorithm").use(PBES2Algorithms),
    this.key("encryptedContent").octstr()
  );
});

Object.assign(ContentInfo.algoModel.IDS, OID);
Object.assign(ContentInfo.algoModel, {
  PBES2: PBES2_params,
  "Dstu7624cbc-256": Dstu7624Parameters
});

var pbes2_parse = function(data) {
  const obj = PBES2.decode(data, "der");
  return [pbes2_parse_asn1(obj)];
};

var pbes2_parse_asn1 = function(asn1) {
  var kdf, enc, params, iv, sbox, salt, iter, keyLength;

  if (asn1.contentEncryptionAlgorithm.algorithm !== "PBES2") {
    throw new Error(asn1.contentEncryptionAlgorithm.algorithm);
  }
  if (asn1.contentEncryptionAlgorithm.parameters.type !== "params") {
    throw new Error(asn1.contentEncryptionAlgorithm.parameters.type);
  }
  kdf = asn1.contentEncryptionAlgorithm.parameters.value.keyDerivationFunc;
  if (kdf.id !== "PBKDF2") {
    throw new Error(kdf.id);
  }
  if (
    kdf.params.hash.algorithm !== "Gost34311-hmac" &&
    kdf.params.hash.algorithm !== "Dstu7564mac-256"
  ) {
    throw new Error("Unknown PBES2 KDF " + kdf.params.hash.algorithm);
  }
  if (kdf.params.hash.parameters.type !== "null_") {
    throw new Error("Unsupported PBES2 KDF parameters");
  }
  enc = asn1.contentEncryptionAlgorithm.parameters.value.encryptionScheme;
  if (
    enc.algorithm !== "Gost28147-cfb" &&
    enc.algorithm !== "Dstu7624cbc-256"
  ) {
    throw new Error("Unknown PBES2 cipher " + enc.algorithm);
  }
  if (
    (kdf.params.hash.algorithm === "Gost34311-hmac" &&
      enc.algorithm !== "Gost28147-cfb") ||
    (kdf.params.hash.algorithm === "Dstu7564mac-256" &&
      enc.algorithm !== "Dstu7624cbc-256")
  ) {
    throw new Error(
      "Unsupported PBES2 profile " +
        kdf.params.hash.algorithm +
        "/" +
        enc.algorithm
    );
  }
  if (enc.parameters.type !== "params") {
    throw new Error("Encryption params not passed");
  }
  params = enc.parameters.value;
  if (params === null) {
    throw new Error("Encryption params not passed");
  }
  iv = params.iv;
  sbox = params.dke;
  salt = kdf.params.salt;
  iter = kdf.params.cycles;
  keyLength = kdf.params.keyLength;

  if (keyLength && keyLength.toNumber() !== 32) {
    throw new Error("Unsupported PBES2 key length");
  }
  iter = iter.toNumber();
  if (
    !Number.isSafeInteger(iter) ||
    iter < 1 ||
    iter > MAX_KDF_ITERATIONS
  ) {
    throw new Error("Invalid PBES2 iteration count");
  }
  if (salt.length === 0 || salt.length > MAX_PBES2_SALT_LENGTH) {
    throw new Error("Invalid PBES2 salt length " + salt.length);
  }
  if (
    enc.algorithm === "Gost28147-cfb" &&
    (iv.length !== 8 || !sbox || sbox.length !== 64)
  ) {
    throw new Error(
      "IV len: " +
        iv.length +
        ", S-BOX len: " +
        (sbox ? sbox.length : 0) +
        ", SALT len: " +
        salt.length
    );
  }
  if (
    enc.algorithm === "Dstu7624cbc-256" &&
    (iv.length !== 32 ||
      asn1.encryptedContent.length === 0 ||
      asn1.encryptedContent.length % 32 !== 0)
  ) {
    throw new Error("Invalid Dstu7624cbc-256 parameters");
  }
  return {
    format: "PBES2",
    kdf: kdf.params.hash.algorithm,
    enc: enc.algorithm,
    iv: iv,
    sbox: sbox,
    salt: salt,
    iters: iter,
    body: asn1.encryptedContent
  };
};

var pbes2_serialize = function(store) {
  if (
    (store.kdf && store.kdf !== "Gost34311-hmac") ||
    (store.enc && store.enc !== "Gost28147-cfb")
  ) {
    throw new Error("PBES2 serialization supports only the legacy GOST profile");
  }
  return PBES2.encode(
    {
      contentEncryptionAlgorithm: {
        algorithm: "PBES2",
        parameters: {
          type: "params",
          value: {
            keyDerivationFunc: {
              id: "PBKDF2",
              params: {
                salt: store.salt,
                cycles: 10000,
                hash: {
                  algorithm: "Gost34311-hmac",
                  parameters: {
                    type: "null_",
                    value: null
                  }
                }
              }
            },
            encryptionScheme: {
              algorithm: "Gost28147-cfb",
              parameters: {
                type: "params",
                value: {
                  iv: store.iv,
                  dke: store.sbox
                }
              }
            }
          }
        }
      },
      encryptedContent: store.body
    },
    "der"
  );
};

PBES2.obj_parse = pbes2_parse_asn1;
PBES2.pbes2_parse = pbes2_parse;

export default PBES2;
export {
  OID,
  pbes2_parse,
  pbes2_serialize as enc_serialize,
  pbes2_parse_asn1 as obj_parse,
  MAX_PBES2_SALT_LENGTH,
  MAX_KDF_ITERATIONS
};
