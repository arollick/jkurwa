import asn1 from "asn1.js";
import PBES2, * as pbes2 from "./pbes.js";
import * as dstszi2010 from "./dstszi2010.js";
import * as rfc3280 from "./rfc3280.js";

const OID = {
  "1 2 840 113549 1 12 10 1 2": "pkcs-12-pkcs-8ShroudedKeyBag",
  "1 2 840 113549 1 12 10 1 3": "pkcs-12-certBag",
  "1 2 840 113549 1 12 10 1 5": "secretBag"
};

const MAX_PFX_PROTECTED_STORES = 16;
const MAX_PFX_TOTAL_KDF_ITERATIONS = 300000;

function pfxError(message) {
  const error = new Error(message);
  error.name = "PFXError";
  return error;
}

const CertBag = asn1.define("CertBag", function() {
  this.seq().obj(
    this.key("id").objid({
      "1 2 840 113549 1 9 22 1": "x509Certificate"
    }),
    this.key("certValue")
      .explicit(0)
      .octstr()
  );
});

// This wraps the bag with unknown id.
// Judging from the id 19398 it's another IIT trap they don't want
// anyone to be able to parse.

const SecretBag = asn1.define("SecretBag", function() {
  this.seq().obj(
    this.key("id").objid(dstszi2010.PKCS7_CONTENT_TYPES),
    this.key("content").any() // this looks like encrypted pkcs7 data
  );
});

const BagModels = {
  "pkcs-12-pkcs-8ShroudedKeyBag": PBES2,
  "pkcs-12-certBag": CertBag,
  secretBag: SecretBag
};

const SafeBag = asn1.define("SafeContents", function() {
  this.seq().obj(
    this.key("bagId").objid(OID),
    this.key("bagValue")
      .explicit(0)
      .use(function(ob) {
        if (!BagModels[ob.bagId]) {
          throw pfxError("Unknown PFX bag id " + ob.bagId);
        }
        return BagModels[ob.bagId];
      }),
    this.key("bagAttributes")
      .set()
      .optional()
  );
});

const SafeContents = asn1.define("SafeContents", function() {
  return this.seqof(SafeBag);
});

const Bags = asn1.define("ContentInfo", function() {
  this.seqof(dstszi2010.ContentInfo);
});

const DigestInfo = asn1.define("DigestInfo", function() {
  this.seq().obj(
    this.key("digestAlgorithm")
      .seq()
      .obj(
        this.key("algorithm").objid({
          "1 2 804 2 1 1 1 1 2 2 1": "Dstu7564-256"
        }),
        this.key("parameters")
          .optional()
          .any()
      ),
    this.key("digest").octstr()
  );
});

const MacData = asn1.define("MacData", function() {
  this.seq().obj(
    this.key("mac").use(DigestInfo),
    this.key("macSalt").octstr(),
    this.key("iterations")
      .optional()
      .int()
  );
});

const PFX = asn1.define("PFX", function() {
  this.seq().obj(
    this.key("version").int(),
    this.key("authSafe").use(dstszi2010.ContentInfo),
    this.key("macData")
      .optional()
      .use(MacData)
  );
});

function pfx_parse(data) {
  const pfx = PFX.decode(data, "der");
  if (pfx.version.toNumber() !== 3) {
    throw pfxError("Unsupported PFX version");
  }
  if (pfx.authSafe.contentType !== "data" || !pfx.authSafe.content) {
    throw pfxError("Unsupported PFX authSafe content");
  }

  const messages = Bags.decode(pfx.authSafe.content, "der");
  const stores = [];
  const ignoredBags = [];
  messages.forEach(msg => {
    if (msg.contentType === "encryptedData") {
      stores.push(pbes2.obj_parse(msg.content.encryptedContentInfo));
      return;
    }
    if (msg.contentType !== "data") {
      throw pfxError("Unsupported PFX authenticated-safe content");
    }

    const bags = SafeContents.decode(msg.content, "der");
    bags.forEach(bag => {
      if (bag.bagId === "pkcs-12-pkcs-8ShroudedKeyBag") {
        stores.push(pbes2.obj_parse(bag.bagValue));
      } else if (bag.bagId !== "pkcs-12-certBag") {
        ignoredBags.push(bag.bagId);
      }
    });
  });

  if (stores.length === 0) {
    throw pfxError("PFX contains no supported protected key stores");
  }

  const strictProfile = stores.some(
    store =>
      store.kdf === "Dstu7564mac-256" && store.enc === "Dstu7624cbc-256"
  );
  if (strictProfile && ignoredBags.length > 0) {
    throw pfxError("Unsupported key-bag content in Kupyna/Kalyna PFX");
  }
  if (strictProfile && !pfx.macData) {
    throw pfxError(
      "Authenticated MacData is required for Kupyna/Kalyna PFX"
    );
  }

  if (pfx.macData) {
    const iterations = pfx.macData.iterations
      ? pfx.macData.iterations.toNumber()
      : 1;
    if (
      !Number.isSafeInteger(iterations) ||
      iterations < 1 ||
      iterations > pbes2.MAX_KDF_ITERATIONS
    ) {
      throw pfxError("Invalid PFX MAC iteration count");
    }
    const pfxMac = {
      algorithm: pfx.macData.mac.digestAlgorithm.algorithm,
      salt: pfx.macData.macSalt,
      iters: iterations,
      digest: pfx.macData.mac.digest,
      authenticatedSafe: pfx.authSafe.content
    };
    if (
      strictProfile &&
      (pfxMac.algorithm !== "Dstu7564-256" ||
        pfxMac.salt.length === 0 ||
        pfxMac.salt.length > pbes2.MAX_PBES2_SALT_LENGTH ||
        pfxMac.digest.length !== 32)
    ) {
      throw pfxError("Invalid Kupyna/Kalyna PFX MacData");
    }
    if (strictProfile) {
      if (stores.length > MAX_PFX_PROTECTED_STORES) {
        throw pfxError("Too many protected stores in Kupyna/Kalyna PFX");
      }
      const totalIterations = stores.reduce(
        (sum, store) => sum + store.iters,
        pfxMac.iters
      );
      if (totalIterations > MAX_PFX_TOTAL_KDF_ITERATIONS) {
        throw pfxError("Kupyna/Kalyna PFX exceeds total KDF work limit");
      }
    }
    stores.forEach(store => {
      store.container = "PFX";
      store.pfxMac = pfxMac;
    });
  } else {
    stores.forEach(store => {
      store.container = "PFX";
    });
  }

  return stores;
}

function certbags_from_asn1(data) {
  const bags = SafeContents.decode(data, "der");
  return bags.map(bag => bag.bagValue.certValue);
}

export {
  MAX_PFX_PROTECTED_STORES,
  MAX_PFX_TOTAL_KDF_ITERATIONS,
  pfx_parse,
  certbags_from_asn1
};
