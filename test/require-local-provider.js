const fs = require("fs");
const path = require("path");

const configuredProvider = process.env.JKURWA_GOST89_PROVIDER;
if (!configuredProvider) {
  console.error("JKURWA_GOST89_PROVIDER must name a gost89 lib/compat.js file");
  process.exit(1);
}

const providerPath = path.resolve(configuredProvider);
let providerStat;
try {
  providerStat = fs.statSync(providerPath);
} catch (error) {
  console.error("JKURWA_GOST89_PROVIDER does not exist: " + providerPath);
  process.exit(1);
}

if (!providerStat.isFile()) {
  console.error("JKURWA_GOST89_PROVIDER is not a file: " + providerPath);
  process.exit(1);
}
