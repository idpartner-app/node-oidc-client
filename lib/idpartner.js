const url = require('node:url');
const { custom, generators, Issuer } = require('openid-client');
const { v4: uuidv4 } = require('uuid');
const jose = require('node-jose');
const { HTTPClient } = require('@idpartner/http-client');
const { logger } = require('@idpartner/logger');

const SIGNING_ALG = 'PS256';
// const ENCRYPTION_ALG = 'RSA-OAEP';
// const ENCRYPTION_ENC = 'A256CBC-HS512';
const DEFAULT_TIMEOUT_IN_MILLIS = 3500;

const createClient = async (config, issuer) => {
  const clientId = config.client_id;
  const clientSecret = config.client_secret;
  const redirectUri = config.callback;
  const jwks = config.jwks;
  custom.setHttpOptionsDefaults({
    timeout: parseInt(config.timeout) || DEFAULT_TIMEOUT_IN_MILLIS,
  });

  return new issuer.Client(
    {
      client_id: clientId,
      client_secret: clientSecret,
      // token_endpoint_auth_method: 'client_secret_basic',
      redirect_uris: redirectUri.split(','),
      // authorization_signed_response_alg: SIGNING_ALG,
      // authorization_encrypted_response_alg: ENCRYPTION_ALG,
      // authorization_encrypted_response_enc: ENCRYPTION_ENC,
      id_token_signed_response_alg: SIGNING_ALG,
      // id_token_encrypted_response_alg: ENCRYPTION_ALG,
      // id_token_encrypted_response_enc: ENCRYPTION_ENC,
      // request_object_signing_alg: SIGNING_ALG,
    },
    // jwks,
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

  async #getAccessToken(client, codeResponse, { state, nonce, codeVerifier }, options={}) {
    // const params = { response: codeResponse };
    const params = client.callbackParams(codeResponse);
    console.log('gio: params idpartner.js', params);
    return client.callback(client.redirect_uris[0], params, { state, nonce, code_verifier: codeVerifier }, options);
  };

  async getPublicJWKs() {
    const keystore = await jose.JWK.asKeyStore(this.config.jwks);
    return keystore.toJSON(false);
  }

  generateProofs() {
    return { state: generators.state(), nonce: generators.nonce(), codeVerifier: generators.codeVerifier() };
  }

  async getAuthorizationUrl(query, proofs, scope, prompt) {
    const {
      client_id: clientId,
      client_secret: clientSecret,
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
    const codeChallenge = generators.codeChallenge(codeVerifier);

    const client = await this.#getClient(iss);
    // const requestObject = client.requestObject({
    return client.authorizationUrl({
      redirect_uri: redirectUri,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      state,
      nonce,
      scope: scope.join(' '),
      prompt,
      response_type: 'code',
      client_id: clientId,
      client_secret: clientSecret,
      nbf: Math.floor(new Date().getTime() / 1000),
      'x-fapi-interaction-id': uuidv4(),
      identity_provider_id: query.idp_id,
      idpartner_token: idpartnerToken,
    });

    // const { request_uri } = await client.pushedAuthorizationRequest({ request: requestObject });
    // const queryParams = new URLSearchParams({ request_uri });
    // return `${client.issuer.authorization_endpoint}?${queryParams}`;
  }

  // Legacy function to fetch the user info using the authorization code. This is an optimization of the more verbose version
  // that requires to first call the `token `function to get the access token and then call the `userInfo` function to get the
  // user info claims. Use this if you need to fetch the user info right after the access token is returned.
  async claims(codeResponse, expectedIssuer, proofs, options={}) {
    const client = await this.#getClient(expectedIssuer);
    const accessToken = await this.#getAccessToken(client, codeResponse, proofs, options);
    return client.userinfo(accessToken, options);
  }

  async token(codeResponse, expectedIssuer, proofs, options={}) {
    const client = await this.#getClient(expectedIssuer);
    return this.#getAccessToken(client, codeResponse, proofs, options);
  }

  async refreshToken(expectedIssuer, refreshToken, options={}) {
    const client = await this.#getClient(expectedIssuer);
    return client.refresh(refreshToken, options);
  }

  async userInfo(expectedIssuer, accessToken, options={}) {
    const client = await this.#getClient(expectedIssuer);
    return client.userinfo(accessToken, options);
  }

  // The unused params below were added to a) be consistent with the interface exposed by the
  // `userInfo` function, and, b) to be able to modify the underlying implementation to make
  // make a request to the OP without changing the interface of the function.
  async basicUserInfo(_expectedIssuer, accessToken, _options={}) {
    return accessToken.claims();
  }

  async paymentDetailsInfo(expectedIssuer, accessToken, options={}) {
    const client = await this.#getClient(expectedIssuer);

    const response = await client.requestResource(client.issuer.payment_details_info_endpoint, accessToken, options);
    const status = response.statusCode;
    if (status >= 400 && status < 600) {
      throw new Error(`Failed to get the bank accounts info. Data: ${response.body}, Status: ${status}`);
    }
    return JSON.parse(response.body);
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
