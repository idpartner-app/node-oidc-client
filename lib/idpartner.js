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
    const {
      client_id: clientId,
      oidc_proxy_service_url: oidcProxyServiceUrl,
      callback: redirectUri
    } = this.config;

    if(!query.iss){
      return `${oidcProxyServiceUrl}/auth/select-accounts?client_id=${clientId}`;
    }
    if (!query) throw new Error('The URL query paramaters are required.');
    if (!proofs) throw new Error('The proofs paramaters are required.');
    if (!scope) throw new Error('The scope paramaters are required.');

    const { state, nonce, codeVerifier } = proofs;
    const proxyIssuer = await Issuer.discover(query.iss);
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const client = await createClient(this.config, proxyIssuer);

    const requestObject = await client.requestObject({
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
      identity_provider_id: query.idp_id,
    });

    const pushedAuthRequest = await client.pushedAuthorizationRequest({ request: requestObject });
    return client.authorizationUrl({ request_uri: pushedAuthRequest.request_uri });
  }

  async claims(codeResponse, iss, { state, nonce, codeVerifier }) {
    const base64Header = codeResponse.split('.')[0];
    const header = JSON.parse(Buffer.from(base64Header, 'base64'));
    if(header.iss !== iss) {
      throw new Error(`iss does not match`)
    }
    const issuer = await Issuer.discover(header.iss);
    const client = await createClient(this.config, issuer);

    // Get access token and user info
    const params = { response: codeResponse };
    const tokenSet = await client.callback(client.redirect_uris[0], params, { jarm: true, state: state, nonce: nonce, code_verifier: codeVerifier });
    return tokenSet.claims();
  }
}

module.exports = IDPartner;
