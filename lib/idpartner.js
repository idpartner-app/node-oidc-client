const { generators, Issuer } = require('openid-client');
const { v4: uuidv4 } = require('uuid');
const { verifyDocument } = require('./document-verifier');
const jose = require('node-jose');

const SIGNING_ALG = 'PS256';
const ENCRYPTION_ALG = 'RSA-OAEP';
const ENCRYPTION_ENC = 'A256CBC-HS512';

const createClient = async (config, issuer) => {
  const clientId = config.client_id;
  const redirectUri = config.callback;
  const jwks = config.jwks;

  return new issuer.Client(
    {
      client_id: clientId,
      token_endpoint_auth_method: 'private_key_jwt',
      redirect_uris: redirectUri.split(','),
      authorization_signed_response_alg: SIGNING_ALG,
      authorization_encrypted_response_alg: ENCRYPTION_ALG,
      authorization_encrypted_response_enc: ENCRYPTION_ENC,
      id_token_signed_response_alg: SIGNING_ALG,
      id_token_encrypted_response_alg: ENCRYPTION_ALG,
      id_token_encrypted_response_enc: ENCRYPTION_ENC,
      userinfo_signed_response_alg: SIGNING_ALG,
      userinfo_encrypted_response_alg: ENCRYPTION_ALG,
      userinfo_encrypted_response_enc: ENCRYPTION_ENC,
      request_object_signing_alg: SIGNING_ALG,
    },
    jwks,
  );
};

class IDPartner {
  constructor(config) {
    if (!config) {
      throw new Error('Config missing. The config object is required to make any call to the ' + 'IDPartner API');
    }
    const defaultConfig = {
      trust_directory_service_url: 'https://auth-api.idpartner.com/trust-directory',
      oidc_proxy_service_url: 'https://auth-api.idpartner.com/oidc-proxy',
      apiVersion: 'v1',
    };

    this.config = {
      ...defaultConfig,
      ...config,
    };
  }

  async getPublicJWKs() {
    const keystore = await jose.JWK.asKeyStore(this.config.jwks);
    return keystore.toJSON(false);
  }

  generateProofs() {
    return { state: generators.state(), nonce: generators.nonce(), codeVerifier: generators.codeVerifier() };
  }

  async getAuthorizationUrl(query, proofs, scope) {
    if (!query) throw new Error('The URL query paramaters are required.');
    if (!proofs) throw new Error('The proofs paramaters are required.');
    if (!scope) throw new Error('The scope paramaters are required.');

    const clientId = this.config.client_id;
    const redirectUri = this.config.callback;

    const { state, nonce, codeVerifier } = proofs;
    const proxyIssuer = await Issuer.discover(this.config.oidc_proxy_service_url);
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const client = await createClient(this.config, proxyIssuer);

    const jwt = await client.requestObject({
      redirect_uri: redirectUri,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      state,
      nonce,
      scope: scope.join(' '),
      response_mode: 'jwt',
      response_type: 'code',
      client_id: clientId,
      nbf: Math.floor(new Date().getTime() / 1000),
      'x-fapi-interaction-id': uuidv4(),
    });
    return `${this.config.oidc_proxy_service_url}/auth?request=${jwt}&visitor_id=${query.visitor_id}`;
  }

  async unpackProxyResponse(query) {
    if (query.error && query.error_description) {
      throw new Error({ error: query.error, error_description: query.error_description });
    }
    // Verify document is signed by IDPartner and get the nested response signed and encrypted by the OIDC Provider
    const { sub: nestedResponse, identity_provider } = await verifyDocument(query.response, this.config);

    return { identity_provider, idp_response_code: nestedResponse };
  }

  async claims(codeResponse, { state, nonce, codeVerifier }) {
    const base64Header = codeResponse.split('.')[0];
    const header = JSON.parse(Buffer.from(base64Header, 'base64'));
    const issuer = await Issuer.discover(header.iss);
    const client = await createClient(this.config, issuer);

    // Get access token and user info
    const params = { response: codeResponse };
    const tokenSet = await client.callback(client.redirect_uris[0], params, { jarm: true, state: state, nonce: nonce, code_verifier: codeVerifier });
    return tokenSet.claims();
  }
}

module.exports = IDPartner;
