const jose = require('node-jose');
const { identityProviderSchema } = require('./document-schemas');
const { getKeyStore } = require('./trust-management-jwks');

const verifyDocumentSignature = async (signedDocument, config) => {
  try {
    const keyStore = await getKeyStore(config);
    const { payload } = await jose.JWS.createVerify(keyStore).verify(signedDocument);
    return payload.toString();
  } catch (error) {
    console.log(error.stack);
    console.error(`Failed to verify document signature. ${error}`);
    throw new Error(`Could not verify document signature using public keys`);
  }
};

const verifyIdentityProviderPackage = async document => {
  const { identity_provider: identityProvider } = document;

  await identityProviderSchema.validateAsync(identityProvider, { presence: 'required', allowUnknown: true });

  return document;
};

const verifyIdPartnerClaims = (document, clientId) => {
  const { aud } = document;

  if (aud !== clientId) {
    throw new Error(`Document aud mismatches. Expected ${aud} but got ${clientId}`);
  }

  return document;
};

exports.verifyDocument = async (signedDocument, config) => {
  // GET JWT from JWS
  const plaintextDocument = await verifyDocumentSignature(signedDocument, config);

  // Parse JWT to an Object
  const document = JSON.parse(plaintextDocument);

  // Verify JWT content
  verifyIdPartnerClaims(document, config.client_id);
  await verifyIdentityProviderPackage(document);

  // Return document as Object
  return document;
};
