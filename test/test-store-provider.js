import { describe, it } from "vitest";
import assert from "assert";
import fs from "fs";
import path from "path";
import { createRequire } from "module";
import asn1 from "asn1.js";

import * as jk from "../lib/index.js";
import PBES2, * as pbes2 from "../lib/spec/pbes.js";
import * as pfxSpec from "../lib/spec/pfx.js";
import { loadPrivPem } from "./utils.js";

const configuredProvider = process.env.JKURWA_GOST89_PROVIDER;
const providerPath = configuredProvider
  ? path.resolve(configuredProvider)
  : null;
const providerAvailable = providerPath && fs.existsSync(providerPath);

const ContentInfo = asn1.define("ProviderTestContentInfo", function() {
  this.seq().obj(
    this.key("contentType").objid({
      "1 2 840 113549 1 7 1": "data"
    }),
    this.key("content")
      .explicit(0)
      .octstr()
  );
});

const SafeBag = asn1.define("ProviderTestSafeBag", function() {
  this.seq().obj(
    this.key("bagId").objid({
      "1 2 840 113549 1 12 10 1 2": "shroudedKeyBag"
    }),
    this.key("bagValue")
      .explicit(0)
      .any()
  );
});

const SafeContents = asn1.define("ProviderTestSafeContents", function() {
  this.seqof(SafeBag);
});

const AuthenticatedSafe = asn1.define(
  "ProviderTestAuthenticatedSafe",
  function() {
    this.seqof(ContentInfo);
  }
);

const MacData = asn1.define("ProviderTestMacData", function() {
  this.seq().obj(
    this.key("mac")
      .seq()
      .obj(
        this.key("digestAlgorithm")
          .seq()
          .obj(
            this.key("algorithm").objid({
              "1 2 804 2 1 1 1 1 2 2 1": "Dstu7564-256"
            }),
            this.key("parameters").null_()
          ),
        this.key("digest").octstr()
      ),
    this.key("macSalt").octstr(),
    this.key("iterations").int()
  );
});

const PFX = asn1.define("ProviderTestPFX", function() {
  this.seq().obj(
    this.key("version").int(),
    this.key("authSafe").use(ContentInfo),
    this.key("macData").use(MacData)
  );
});

function pkcs7Pad(data, blockSize) {
  const pad = blockSize - (data.length % blockSize);
  return Buffer.concat([data, Buffer.alloc(pad, pad)]);
}

describe("local Kupyna/Kalyna provider integration", () => {
  const run = providerAvailable ? it : it.skip;

  run("loads a disposable authenticated PFX through gost89", () => {
    const requireProvider = createRequire(providerPath);
    const provider = requireProvider(providerPath);
    const dstu7624 = requireProvider("dstu7624");
    const providerPackage = JSON.parse(
      fs.readFileSync(path.resolve(path.dirname(providerPath), "../package.json"))
    );
    assert.equal(providerPackage.version, "0.1.12");
    assert.equal(
      provider.MAX_PBES2_SALT_LENGTH,
      pbes2.MAX_PBES2_SALT_LENGTH
    );
    assert.equal(provider.MAX_KDF_ITERATIONS, pbes2.MAX_KDF_ITERATIONS);
    assert.equal(
      provider.MAX_PFX_PROTECTED_STORES,
      pfxSpec.MAX_PFX_PROTECTED_STORES
    );
    assert.equal(
      provider.MAX_PFX_TOTAL_KDF_ITERATIONS,
      pfxSpec.MAX_PFX_TOTAL_KDF_ITERATIONS
    );

    const password = "disposable-password";
    const salt = Buffer.alloc(20, 0x11);
    const iv = Buffer.alloc(32, 0x22);
    const iterations = 2;
    const priv = loadPrivPem("Key40A0.pem");
    const raw = Buffer.from(priv.to_asn1());
    const params = {
      format: "PBES2",
      kdf: "Dstu7564mac-256",
      enc: "Dstu7624cbc-256",
      salt,
      iv,
      iters: iterations
    };
    const key = provider.convert_password(params, password);
    const body = dstu7624.cbcEncrypt(key, iv, pkcs7Pad(raw, 32));
    const pbes = PBES2.encode(
      {
        contentEncryptionAlgorithm: {
          algorithm: "PBES2",
          parameters: {
            type: "params",
            value: {
              keyDerivationFunc: {
                id: "PBKDF2",
                params: {
                  salt,
                  cycles: iterations,
                  hash: {
                    algorithm: "Dstu7564mac-256",
                    parameters: { type: "null_", value: null }
                  }
                }
              },
              encryptionScheme: {
                algorithm: "Dstu7624cbc-256",
                parameters: { type: "params", value: { iv } }
              }
            }
          }
        },
        encryptedContent: body
      },
      "der"
    );
    const safeContents = SafeContents.encode(
      [{ bagId: "shroudedKeyBag", bagValue: pbes }],
      "der"
    );
    const authenticatedSafe = AuthenticatedSafe.encode(
      [{ contentType: "data", content: safeContents }],
      "der"
    );
    const macSalt = Buffer.alloc(20, 0x33);
    const mac = provider.pfx_mac(password, {
      salt: macSalt,
      iters: iterations,
      authenticatedSafe
    });
    const pfx = PFX.encode(
      {
        version: 3,
        authSafe: { contentType: "data", content: authenticatedSafe },
        macData: {
          mac: {
            digestAlgorithm: {
              algorithm: "Dstu7564-256",
              parameters: null
            },
            digest: mac
          },
          macSalt,
          iterations
        }
      },
      "der"
    );

    const loaded = jk.Priv.from_protected(pfx, password, provider.algos());
    assert.deepEqual(loaded.keys, [priv]);
    assert.throws(
      () =>
        jk.Priv.from_protected(
          pfx,
          "deterministically-wrong-password",
          provider.algos()
        ),
      /Invalid PFX password or integrity check/
    );
  });
});
