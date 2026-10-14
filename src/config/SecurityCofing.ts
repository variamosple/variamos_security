import { createPrivateKey, createPublicKey, KeyObject } from "crypto";
import fs from "fs";
import path from "path";

const encodig = "utf8";
export const PRIVATE_KEY_ID = "private-signing-key";
export const PUBLIC_KEY_ID = "public-verification-key";

const keyStore = new Map<string, KeyObject>();

/**
 * Stores a key under its key ID. The first key added under a given ID wins,
 * as it did with the previous node-jose key store.
 */
const addKey = (kid: string, key: KeyObject) => {
  if (!keyStore.has(kid)) {
    keyStore.set(kid, key);
  }
};

/**
 * Initializes the key store by loading and adding public and private keys from the filesystem.
 *
 * Reads the private key from the path specified in the environment variable `VARIAMOS_PRIVATE_KEY_PATH`
 * and the public key from the path specified in `VARIAMOS_PUBLIC_KEY_PATH`.
 *
 * The private key is added to the key store with a key ID (`kid`) of "private-signing-key".
 * The public key is added to the key store with a key ID of "public-verification-key".
 *
 * Logs a success message with the key IDs held by the key store if initialization is successful.
 * Logs an error message if an exception is caught during the process.
 *
 * @returns {Promise<void>} - A promise that resolves when the key store is initialized.
 *
 * @throws {Error} - Throws an error if reading keys from the file system or adding them to the key store fails.
 */
export const initKeyStore = async () => {
  try {
    const privateKeyPath = process.env.VARIAMOS_PRIVATE_KEY_PATH;
    if (!!privateKeyPath) {
      const privateKeyPEM = fs.readFileSync(
        path.resolve(process.cwd(), privateKeyPath),
        encodig
      );

      addKey(PRIVATE_KEY_ID, createPrivateKey(privateKeyPEM));
    }

    const publicKeyPath = process.env.VARIAMOS_PUBLIC_KEY_PATH;

    if (!!publicKeyPath) {
      const publicKeyPEM = fs.readFileSync(
        path.resolve(process.cwd(), publicKeyPath),
        encodig
      );

      addKey(PUBLIC_KEY_ID, createPublicKey(publicKeyPEM));
    }

    console.info(
      "VariaMos-security keystore initilized successfully!",
      Array.from(keyStore.keys())
    );
  } catch (err) {
    console.error("Error creating VariaMos-security keystore:", err);
  }
};

/**
 * Retrieves the public key from the key store.
 *
 * @returns {KeyObject | undefined} - The public key, or `undefined` if the key store holds none.
 */
export const getPublicKey = (): KeyObject | undefined =>
  keyStore.get(PUBLIC_KEY_ID);

/**
 * Retrieves the private key from the key store.
 *
 * @returns {KeyObject | undefined} - The private key, or `undefined` if the key store holds none.
 */
export const getPrivateKey = (): KeyObject | undefined =>
  keyStore.get(PRIVATE_KEY_ID);
