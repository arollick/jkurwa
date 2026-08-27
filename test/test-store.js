import { describe, it } from "vitest";
import assert from "assert";
import asn1 from "asn1.js";
import { algos } from "gost89/lib/compat.js";

import * as jk from "../lib/index.js";
import PBES2, * as pbes2 from "../lib/spec/pbes.js";
import * as pfx from "../lib/spec/pfx.js";
import * as pem from "../lib/util/pem.js";
import { loadAsset, loadPrivPem, assertEqualSaved } from "./utils.js";

const algo = algos();

const TestContentInfo = asn1.define("TestContentInfo", function() {
  this.seq().obj(
    this.key("contentType").objid({
      "1 2 840 113549 1 7 1": "data"
    }),
    this.key("content")
      .explicit(0)
      .octstr()
  );
});

const TestSafeBag = asn1.define("TestSafeBag", function() {
  this.seq().obj(
    this.key("bagId").objid({
      "1 2 840 113549 1 12 10 1 2": "shroudedKeyBag",
      "1 2 840 113549 1 12 10 1 3": "certBag",
      "1 2 840 113549 1 12 10 1 5": "secretBag"
    }),
    this.key("bagValue")
      .explicit(0)
      .any()
  );
});

const TestCertBag = asn1.define("TestCertBag", function() {
  this.seq().obj(
    this.key("id").objid({
      "1 2 840 113549 1 9 22 1": "x509Certificate"
    }),
    this.key("certValue")
      .explicit(0)
      .octstr()
  );
});

const TestSecretBag = asn1.define("TestSecretBag", function() {
  this.seq().obj(
    this.key("id").objid({
      "1 2 840 113549 1 7 1": "data"
    }),
    this.key("content").any()
  );
});

const TestSafeContents = asn1.define("TestSafeContents", function() {
  this.seqof(TestSafeBag);
});

const TestAuthenticatedSafe = asn1.define("TestAuthenticatedSafe", function() {
  this.seqof(TestContentInfo);
});

const TestMacData = asn1.define("TestMacData", function() {
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

const TestPFX = asn1.define("TestPFX", function() {
  this.seq().obj(
    this.key("version").int(),
    this.key("authSafe").use(TestContentInfo),
    this.key("macData")
      .optional()
      .use(TestMacData)
  );
});

function wrapPfxBags(bags, macData) {
  const safeContents = TestSafeContents.encode(
    bags,
    "der"
  );
  const authenticatedSafe = TestAuthenticatedSafe.encode(
    [{ contentType: "data", content: safeContents }],
    "der"
  );
  const pfx = {
    version: 3,
    authSafe: { contentType: "data", content: authenticatedSafe }
  };
  if (macData) {
    pfx.macData = macData;
  }
  return TestPFX.encode(pfx, "der");
}

function wrapPfx(pbes, macData) {
  return wrapPfxBags(
    [{ bagId: "shroudedKeyBag", bagValue: pbes }],
    macData
  );
}

function testMacData(overrides = {}) {
  return {
    mac: {
      digestAlgorithm: {
        algorithm: "Dstu7564-256",
        parameters: null
      },
      digest: overrides.digest || Buffer.alloc(32, 0x55)
    },
    macSalt: overrides.macSalt || Buffer.alloc(20, 0x66),
    iterations: overrides.iterations || 10000
  };
}

function kupynaPbes2(options = {}) {
  const encryptionAlgorithm =
    options.encryptionAlgorithm || "Dstu7624cbc-256";
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
                salt:
                  options.salt === undefined
                    ? Buffer.alloc(32, 0x11)
                    : options.salt,
                cycles:
                  options.iterations === undefined ? 10000 : options.iterations,
                hash: {
                  algorithm: "Dstu7564mac-256",
                  parameters: { type: "null_", value: null }
                }
              }
            },
            encryptionScheme:
              encryptionAlgorithm === "Dstu7624cbc-256"
                ? {
                    algorithm: encryptionAlgorithm,
                    parameters: {
                      type: "params",
                      value: { iv: Buffer.alloc(32, 0x22) }
                    }
                  }
                : {
                    algorithm: encryptionAlgorithm,
                    parameters: {
                      type: "params",
                      value: {
                        iv: Buffer.alloc(8, 0x22),
                        dke: Buffer.alloc(64, 0x33)
                      }
                    }
                  }
          }
        }
      },
      encryptedContent: options.body || Buffer.alloc(32, 0x44)
    },
    "der"
  );
}

describe("Keycoder", () => {
  const enc = loadAsset("STORE_A040.dat");
  const encPem = loadAsset("STORE_A040.pem").toString();
  const priv = loadPrivPem("Key40A0.pem");

  describe("#parse()", () => {
    it("should parse encrypted key in PEM format", () => {
      const [store] = jk.guess_parse(enc);
      assert.equal(store.format, "PBES2");
      assert.equal(store.kdf, "Gost34311-hmac");
      assert.equal(store.enc, "Gost28147-cfb");
    });

    it("should parse a legacy PBES2 key from a structural PFX envelope", () => {
      const [store] = pfx.pfx_parse(wrapPfx(enc));
      assert.equal(store.kdf, "Gost34311-hmac");
      assert.equal(store.enc, "Gost28147-cfb");
      assert.deepEqual(store.body, jk.guess_parse(enc)[0].body);
    });

    it("should hand off the Kupyna/Kalyna PFX profile metadata", () => {
      const [store] = pfx.pfx_parse(
        wrapPfx(kupynaPbes2(), testMacData())
      );
      assert.equal(store.format, "PBES2");
      assert.equal(store.kdf, "Dstu7564mac-256");
      assert.equal(store.enc, "Dstu7624cbc-256");
      assert.equal(store.salt.length, 32);
      assert.equal(store.iv.length, 32);
      assert.equal(store.body.length, 32);
      assert.equal(store.pfxMac.algorithm, "Dstu7564-256");
      assert.equal(store.pfxMac.digest.length, 32);
      assert.equal(store.pfxMac.salt.length, 20);
      assert.equal(store.pfxMac.iters, 10000);
    });

    it("should pass the Kupyna/Kalyna metadata to the store provider", () => {
      const loaded = jk.Priv.from_protected(
        wrapPfx(kupynaPbes2(), testMacData()),
        "disposable-password",
        {
          storeload(store) {
            assert.equal(store.kdf, "Dstu7564mac-256");
            assert.equal(store.enc, "Dstu7624cbc-256");
            return Buffer.from(priv.to_asn1());
          }
        }
      );
      assert.deepEqual(loaded.keys, [priv]);
    });

    it("should reject a mismatched PBES2 profile", () => {
      assert.throws(
        () =>
          pbes2.pbes2_parse(
            kupynaPbes2({ encryptionAlgorithm: "Gost28147-cfb" })
          ),
        /Unsupported PBES2 profile/
      );
    });

    it("should accept 20-byte and 32-byte PBES2 salts", () => {
      assert.equal(
        pbes2.pbes2_parse(kupynaPbes2({ salt: Buffer.alloc(20) }))[0].salt
          .length,
        20
      );
      assert.equal(pbes2.pbes2_parse(kupynaPbes2())[0].salt.length, 32);
    });

    it("should reject empty and oversized PBES2 salts", () => {
      assert.throws(
        () => pbes2.pbes2_parse(kupynaPbes2({ salt: Buffer.alloc(0) })),
        /Invalid PBES2 salt length/
      );
      assert.throws(
        () =>
          pbes2.pbes2_parse(
            kupynaPbes2({
              salt: Buffer.alloc(pbes2.MAX_PBES2_SALT_LENGTH + 1)
            })
          ),
        /Invalid PBES2 salt length/
      );
    });

    it("should reject over-limit PBES2 and PFX MAC iterations", () => {
      assert.throws(
        () =>
          pbes2.pbes2_parse(
            kupynaPbes2({ iterations: pbes2.MAX_KDF_ITERATIONS + 1 })
          ),
        /Invalid PBES2 iteration count/
      );
      assert.throws(
        () =>
          pfx.pfx_parse(
            wrapPfx(
              kupynaPbes2(),
              testMacData({ iterations: pbes2.MAX_KDF_ITERATIONS + 1 })
            )
          ),
        /Invalid PFX MAC iteration count/
      );
    });

    it("should accept multiple protected stores within the PFX work budget", () => {
      const stores = pfx.pfx_parse(
        wrapPfxBags(
          [
            {
              bagId: "shroudedKeyBag",
              bagValue: kupynaPbes2({ iterations: 1 })
            },
            {
              bagId: "shroudedKeyBag",
              bagValue: kupynaPbes2({ iterations: 1 })
            }
          ],
          testMacData({ iterations: 1 })
        )
      );
      assert.equal(stores.length, 2);
    });

    it("should reject too many protected stores in a Kupyna/Kalyna PFX", () => {
      const bags = Array.from(
        { length: pfx.MAX_PFX_PROTECTED_STORES + 1 },
        () => ({
          bagId: "shroudedKeyBag",
          bagValue: kupynaPbes2({ iterations: 1 })
        })
      );
      assert.throws(
        () =>
          pfx.pfx_parse(
            wrapPfxBags(bags, testMacData({ iterations: 1 }))
          ),
        /Too many protected stores/
      );
    });

    it("should reject aggregate PFX KDF work above the supported limit", () => {
      const bags = Array.from({ length: 3 }, () => ({
        bagId: "shroudedKeyBag",
        bagValue: kupynaPbes2({ iterations: pbes2.MAX_KDF_ITERATIONS })
      }));
      assert.throws(
        () =>
          pfx.pfx_parse(
            wrapPfxBags(bags, testMacData({ iterations: 1 }))
          ),
        /exceeds total KDF work limit/
      );
    });

    it("should require MacData for the Kupyna/Kalyna PFX profile", () => {
      assert.throws(
        () => pfx.pfx_parse(wrapPfx(kupynaPbes2())),
        /Authenticated MacData is required/
      );
      assert.throws(
        () =>
          jk.Priv.from_protected(
            wrapPfx(kupynaPbes2()),
            "disposable-password",
            { storeload() {} }
          ),
        /Authenticated MacData is required/
      );
    });

    it("should reject a PFX without a supported protected key store", () => {
      const certBag = TestCertBag.encode(
        { id: "x509Certificate", certValue: Buffer.from([0x30, 0x00]) },
        "der"
      );
      assert.throws(
        () =>
          pfx.pfx_parse(
            wrapPfxBags([{ bagId: "certBag", bagValue: certBag }])
          ),
        /no supported protected key stores/
      );
    });

    it("should reject unsupported key bags in a strict profile", () => {
      const secretBag = TestSecretBag.encode(
        {
          id: "data",
          content: Buffer.from([0x05, 0x00])
        },
        "der"
      );
      assert.throws(
        () =>
          pfx.pfx_parse(
            wrapPfxBags(
              [
                { bagId: "shroudedKeyBag", bagValue: kupynaPbes2() },
                { bagId: "secretBag", bagValue: secretBag }
              ],
              testMacData()
            )
          ),
        /Unsupported key-bag content/
      );
    });

    it("should serialize encrypted key to asn1", () => {
      const [store] = jk.guess_parse(enc);
      assert.deepEqual(pbes2.enc_serialize(store), enc);
    });

    it("should serialize encrypted key to PEM", () => {
      const [store] = jk.guess_parse(enc);
      assert.deepEqual(
        pem.to_pem(pbes2.enc_serialize(store), "ENCRYPTED PRIVATE KEY"),
        encPem
      );
    });

    it("should decrypt raw key from PBES2", () => {
      const {
        keys: [key]
      } = jk.Priv.from_protected(enc, "password", algo);
      assert.deepEqual(key, priv);
    });

    it("should decrypt raw key from PBES2 (PEM)", () => {
      const {
        keys: [key]
      } = jk.Priv.from_protected(encPem, "password", algo);
      assert.deepEqual(key, priv);
    });

    it("should encrypt raw key and serialize into PBES2", () => {
      const iv = Buffer.from("4bb10f5c2945d49e", "hex");
      const salt = Buffer.from(
        "31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876",
        "hex"
      );
      const store = algo.storesave(
        Buffer.from(priv.to_asn1()),
        "PBES2",
        "password",
        iv,
        salt
      );

      assertEqualSaved(pbes2.enc_serialize(store), "STORE_A040.dat");
    });
  });
});
