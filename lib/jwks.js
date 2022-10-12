const jose = require('node-jose');

const getKeyStore = (jwks) => {
  if (!jwks) {
    throw new Error(`Missing jwks`);
  }
  return jose.JWK.asKeyStore(jwks.toString());
};

export const getJWKs = async (jwks) => {
  const KeyStore = await getKeyStore(jwks);
  return KeyStore.toJSON(false);
};


