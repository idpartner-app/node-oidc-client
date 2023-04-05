const { custom, generators, Issuer } = require('openid-client');
const { v4: uuidv4 } = require('uuid');
const jose = require('node-jose');
const HTTPClient = require('@idpartner/http-client');
const { logger } = require('@idpartner/logger');

const SIGNING_ALG = 'PS256';
const ENCRYPTION_ALG = 'RSA-OAEP';
const ENCRYPTION_ENC = 'A256CBC-HS512';
const DEFAULT_TIMEOUT_IN_MILLIS = 3500;

const createClient = async (config, issuer) => {
  const clientId = config.client_id;
  const redirectUri = config.callback;
  const jwks = config.jwks;
  custom.setHttpOptionsDefaults({
    timeout: parseInt(config.timeout) || DEFAULT_TIMEOUT_IN_MILLIS,
  });

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
      request_object_signing_alg: SIGNING_ALG,
    },
    jwks,
  );
};

const createHttpClient = iss => HTTPClient({ baseURL: iss, logger });;

class IDPartner {
  constructor(config) {
    if (!config) {
      throw new Error('Config missing. The config object is required to make any call to the ' + 'IDPartner API');
    }
    const defaultConfig = {
      account_selector_service_url: 'https://auth-api.idpartner.com/oidc-proxy',
      apiVersion: 'v1',
    };

    this.config = {
      ...defaultConfig,
      ...config,
    };
  }

  async #getClient(expectedIssuer) {
    const issuer = await Issuer.discover(expectedIssuer);
    return createClient(this.config, issuer);
  }

  async #getAccessToken(client, codeResponse, { state, nonce, codeVerifier }) {
    const params = { response: codeResponse };
    return client.callback(client.redirect_uris[0], params, { jarm: true, state, nonce, code_verifier: codeVerifier });
  };

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
      account_selector_service_url: accountSelectorServiceUrl,
      callback: redirectUri
    } = this.config;

    if (!query) throw new Error('The URL query paramaters are required.');
    if (!proofs) throw new Error('The proofs paramaters are required.');
    if (!scope) throw new Error('The scope paramaters are required.');

    const { iss, visitor_id: visitorId, idpartner_token: idpartnerToken } = query;
    if (!iss) {
      return `${accountSelectorServiceUrl}/auth/select-accounts?client_id=${clientId}&visitor_id=${visitorId}&scope=${scope.join(' ')}`;
    }

    const { state, nonce, codeVerifier } = proofs;
    const issuer = await Issuer.discover(iss);
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const client = await createClient(this.config, issuer);

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
      idpartner_token: idpartnerToken,
    });

    const { request_uri } = await client.pushedAuthorizationRequest({ request: requestObject });
    const queryParams = new URLSearchParams({ request_uri });
    return `${client.issuer.authorization_endpoint}?${queryParams}`
  }

  // Legacy function to fetch the userinfo using the authorization code. This is an optimization of the more verbose version
  // that requires to first call a function to get the access token and then call another one to get the userinfo. Use this
  // if you need to fetch the userinfo synchrounously without relying on theasync flow that uses refresh tokens.
  async claims(codeResponse, expectedIssuer, proofs) {
    const client = await this.#getClient(expectedIssuer);
    const accessToken = await this.#getAccessToken(client, codeResponse, proofs);
    return client.userinfo(accessToken);
  }

  async token(codeResponse, expectedIssuer, proofs) {
    const client = await this.#getClient(expectedIssuer);
    return this.#getAccessToken(client, codeResponse, proofs);
  }

  async refreshToken(expectedIssuer, refreshToken) {
    const client = await this.#getClient(expectedIssuer);
    return client.refresh(refreshToken);
  }

  async userInfo(expectedIssuer, accessToken) {
    const client = await this.#getClient(expectedIssuer);
    return client.userinfo(accessToken);
  }

  async basicUserInfo(_expectedIssuer, accessToken) {
    return accessToken.claims();
  }

  async credential(expectedIssuer, accessToken, body) {
    const httpClient = createHttpClient(expectedIssuer);

    const { data, status } = await httpClient.get('/.well-known/openid-credential-issuer');
    if (status !== 200) {
      throw new Error(`Failed to get the verifiable credential issuer configuration. Status: ${status}`);
    }
    const credentialEndpoint = new URL(data.credential_endpoint);
    return httpClient.post(
      credentialEndpoint.pathname,
      body,
      {
        headers: {
          Authorization: `Bearer ${accessToken.access_token}`,
        }
      }
    );
  }
}

module.exports = IDPartner;
