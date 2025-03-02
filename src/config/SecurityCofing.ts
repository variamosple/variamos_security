import fs from "fs";
import jose from "node-jose";
import path from "path";

const encodig = "utf8";
const keyStore = jose.JWK.createKeyStore();

/**
 * Initializes the key store by loading and adding public and private keys from the filesystem.
 *
 * Reads the private key from the path specified in the environment variable `VARIAMOS_PRIVATE_KEY_PATH`
 * and the public key from the path specified in `VARIAMOS_PUBLIC_KEY_PATH`.
 *
 * The private key is added to the key store with a key ID (`kid`) of "private-signing-key" and usage set to "sig" (signature).
 * The public key is added to the key store with a key ID of "public-verification-key" and usage set to "sig" (signature).
 *
 * Logs a success message with the contents of the key store if initialization is successful.
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

      await keyStore.add(privateKeyPEM, "pem", {
        kid: "private-signing-key",
        use: "sig",
      });
    }

    const publicKeyPath = process.env.VARIAMOS_PUBLIC_KEY_PATH;

    if (!!publicKeyPath) {
      const publicKeyPEM = fs.readFileSync(
        path.resolve(process.cwd(), publicKeyPath),
        encodig
      );

      await keyStore.add(publicKeyPEM, "pem", {
        kid: "public-verification-key",
        use: "sig",
      });
    }

    console.info(
      "VariaMos-security keystore initilized successfully!",
      keyStore.all()
    );
  } catch (err) {
    console.error("Error creating VariaMos-security keystore:", err);
  }
};

/**
 * Retrieves the public key from the key store.
 *
 * @returns {Promise<jose.JWK.Key>} - A promise that resolves with the public key from the key store.
 */
export const getPublicKey = () => keyStore.get("public-verification-key");

/**
 * Retrieves the private key from the key store.
 *
 * @returns {Promise<jose.JWK.Key>} - A promise that resolves with the private key from the key store.
 */
export const getPrivateKey = () => keyStore.get("private-signing-key");
