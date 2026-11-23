// Signs a session token with the built Node library, for the tests of the
// Python package (python/tests): the Python verifier must accept what the
// Node issuer signs. Writes a fresh key pair of the test alone into the
// given directory and prints the token on stdout.
//
//   npm run build && node scripts/python-test-token.mjs <directory>

import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const directory = process.argv[2];
if (!directory) {
  console.error("usage: node scripts/python-test-token.mjs <directory>");
  process.exit(2);
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});
const privatePath = path.join(directory, "private.pem");
fs.writeFileSync(privatePath, privateKey);
fs.writeFileSync(path.join(directory, "public.pem"), publicKey);

process.env.VARIAMOS_PRIVATE_KEY_PATH = privatePath;
process.env.VARIAMOS_JWT_EXP_IN_SECONDS = "900";

const { createJwt, initKeyStore } = await import("../dist/index.mjs");
await initKeyStore();
const token = await createJwt(
  {
    id: "user-1",
    name: "Node Signed",
    user: "node-signed",
    email: "node-signed@example.com",
    roles: ["Developer"],
    permissions: ["projects::query"],
  },
  "app.variamos.com",
);
process.stdout.write(token);
