import jose from 'node-jose';
import { getKeyStore as getTrustManagementKeyStore } from './jwks';
import { identityProviderSchema } from './document-schemas';

const verifyDocumentSignature = async signedDocument => {
  try {
    const keyStore = await getTrustManagementKeyStore();
    const { payload } = await jose.JWS.createVerify(keyStore).verify(signedDocument);
    return payload.toString();
  } catch (error) {
    console.error(`Failed to verify document signature. ${error}`);
    throw new Error(`Could not verify document signature using public keys`);
  }
};

const verifyIdentityProviderPackage = async (document, _session) => {
  const { identity_provider: identityProvider } = document;

  await identityProviderSchema.validateAsync(identityProvider, { presence: 'required', allowUnknown: true });

  return document;
};

const verifyIdPartnerClaims = (document, session) => {
  const { aud } = document;

  if (aud !== session.clientId) {
    throw new Error('Document aud mismatches');
  }

  return document;
};

export const verifyDocument = async (signedDocument, session) => {
  // GET JWT from JWS
  const plaintextDocument = await verifyDocumentSignature(signedDocument);

  // Parse JWT to an Object
  const document = JSON.parse(plaintextDocument);

  // Verify JWT content
  verifyIdPartnerClaims(document, session);
  await verifyIdentityProviderPackage(document, session);

  // Return document as Object
  return document;
};
