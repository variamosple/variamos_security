// Signs a session token with the built Node library, for the tests of the
// Python package (python/tests): the Python verifier must accept what the
// Node issuer signs. Uses a fresh key pair of the test alone, whose private
// key is written to a temporary folder of its own and removed once read.
// Prints {"token": ..., "publicKey": ...} on stdout.
//
//   npm run build && node scripts/python-test-token.mjs

import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

// The library reads its key from a file
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "variamos-token-"));
try {
  const privatePath = path.join(directory, "private.pem");
  fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
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
  process.stdout.write(JSON.stringify({ token, publicKey }));
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
