const { custom, generators, Issuer } = require('openid-client');
const { v4: uuidv4 } = require('uuid');
const JOSEWrapper = require('@idpartner/jose-wrapper');
const { HTTPClient } = require('@idpartner/http-client');
const { logger } = require('@idpartner/logger');

const SUPPORTED_AUTH_METHODS = [
  'client_secret_basic',
  'tls_client_auth',
  'private_key_jwt', // For backward compatibility
];

const SIGNING_ALG = 'PS256';
const ENCRYPTION_ALG = 'RSA-OAEP';
const ENCRYPTION_ENC = 'A256CBC-HS512';
const DEFAULT_TIMEOUT_IN_MILLIS = 3500;

const createHttpClient = iss => HTTPClient({ baseURL: iss, logger });

const getClientConfig = config => {
  let clientSecretConfig = {};
  if (config.token_endpoint_auth_method === 'client_secret_basic') {
    clientSecretConfig = {
      client_secret: config.client_secret,
    };
  }

  let tlsConfig = {};
  if (config.token_endpoint_auth_method === 'tls_client_auth') {
    tlsConfig = {
      tls_client_certificate_bound_access_tokens: true,
    };
  }

  let jwksConfig = {};
  if (config.jwks) {
    jwksConfig = {
      authorization_encrypted_response_alg: ENCRYPTION_ALG,
      authorization_encrypted_response_enc: ENCRYPTION_ENC,
      id_token_encrypted_response_alg: ENCRYPTION_ALG,
      id_token_encrypted_response_enc: ENCRYPTION_ENC,
      request_object_signing_alg: SIGNING_ALG,
    };
  }

  return {
    client_id: config.client_id,
    token_endpoint_auth_method: config.token_endpoint_auth_method,
    redirect_uris: config.callback.split(','),
    authorization_signed_response_alg: SIGNING_ALG,
    id_token_signed_response_alg: SIGNING_ALG,
    ...clientSecretConfig,
    ...tlsConfig,
    ...jwksConfig,
  };
};

const createClient = async (config, issuer) => {
  custom.setHttpOptionsDefaults({
    timeout: parseInt(config.timeout) || DEFAULT_TIMEOUT_IN_MILLIS,
  });

  const clientConfig = getClientConfig(config);
  const client = new issuer.Client(clientConfig, config.jwks);

  if (config.token_endpoint_auth_method === 'tls_client_auth') {
    client[custom.http_options] = (url, _options) => {
      const serverCA = config.tls_server_ca ? { ca: config.tls_server_ca } : {};

      return {
        ...url,
        ...serverCA,
        cert: config.tls_client_cert,
        key: config.tls_client_key,
      };
    };
  }

  return client;
};

class IDPartner {
  constructor(config) {
    if (!config) {
      throw new Error('Config missing. The config object is required to make any call to the ' + 'IDPartner API');
    }

    const defaultConfig = {
      // generic config
      account_selector_service_url: 'https://auth-api.idpartner.com/oidc-proxy',
      token_endpoint_auth_method: 'client_secret_basic',
      jwks: undefined,

      // client_secret_basic auth method config
      client_secret: undefined,

      // tls_client_auth auth method config
      tls_server_ca: undefined,
      tls_client_cert: undefined,
      tls_client_key: undefined,
    };

    this.config = {
      ...defaultConfig,
      ...config,
    };

    if (!SUPPORTED_AUTH_METHODS.includes(this.config.token_endpoint_auth_method)) {
      throw new Error(`Unsupported token_endpoint_auth_method '${config.token_endpoint_auth_method}'. It must be one of (${SUPPORTED_AUTH_METHODS.join(', ')})`);
    }
  }

  async #getClient(expectedIssuer) {
    const issuer = await Issuer.discover(expectedIssuer);
    return createClient(this.config, issuer);
  }

  async #getAccessToken(client, codeResponse, { state, nonce, codeVerifier }, options = {}) {
    const params = client.callbackParams(codeResponse);
    return client.callback(client.redirect_uris[0], params, { state, nonce, code_verifier: codeVerifier }, options);
  }

  async getPublicJWKs() {
    if (!this.config.jwks) {
      return {};
    }

    return JOSEWrapper.getJWKs({ jwks: this.config.jwks, includePrivateKeys: false });
  }

  generateProofs() {
    return {
      state: generators.state(),
      nonce: generators.nonce(),
      codeVerifier: generators.codeVerifier(),
    };
  }

  #extractClaims(claimsObject) {
    if (claimsObject && claimsObject.constructor === Object) {
      let userinfo_keys = Object.keys(claimsObject.userinfo || {});
      let id_token_keys = Object.keys(claimsObject.id_token || {});
      return [...new Set([...userinfo_keys, ...id_token_keys])];
    } else {
      return [];
    }
  }

  async getAuthorizationUrl(query, proofs, scope, extraAuthorizationParams = {}) {
    const { client_id: clientId, account_selector_service_url: accountSelectorServiceUrl, callback: redirectUri } = this.config;
    const { claims, ...otherAuthorizationParams } = extraAuthorizationParams;

    if (!query) throw new Error('The query param is required.');
    if (!proofs) throw new Error('The proofs param is required.');
    if (!scope) throw new Error('The authorizationParams.scope param is required.');

    const claimsArray = this.#extractClaims(claims);
    const claimsString = claimsArray.join(' ');
    const scopeString = typeof scope === 'string' ? scope : scope.join(' ');
    const { iss, visitor_id: visitorId, idpartner_token: idpartnerToken } = query;
    if (!iss) {
      return `${accountSelectorServiceUrl}/auth/select-accounts?client_id=${clientId}&visitor_id=${visitorId}&scope=${scopeString}&claims=${claimsString}`;
    }

    const { state, nonce, codeVerifier } = proofs;
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const client = await this.#getClient(iss);
    const authorizationParams = {
      redirect_uri: redirectUri,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      state,
      nonce,
      scope: scopeString,
      response_type: 'code',
      client_id: clientId,
      nbf: Math.floor(new Date().getTime() / 1000),
      'x-fapi-interaction-id': uuidv4(),
      identity_provider_id: query.idp_id,
      idpartner_token: idpartnerToken,
      response_mode: 'jwt',
      claims: JSON.stringify(claims),
      ...otherAuthorizationParams,
    };

    let pushedAuthorizationRequestParams = authorizationParams;
    if (this.config.jwks) {
      // Generate a request object if jwks are configured
      pushedAuthorizationRequestParams = {
        request: await client.requestObject(authorizationParams),
      };
    }

    const { request_uri } = await client.pushedAuthorizationRequest(pushedAuthorizationRequestParams);
    const queryParams = new URLSearchParams({ request_uri });
    return `${client.issuer.authorization_endpoint}?${queryParams}`;
  }

  // Legacy function to fetch the user info using the authorization code. This is an optimization of the more verbose version
  // that requires to first call the `token `function to get the access token and then call the `userInfo` function to get the
  // user info claims. Use this if you need to fetch the user info right after the access token is returned.
  async claims(codeResponse, expectedIssuer, proofs, options = {}) {
    const client = await this.#getClient(expectedIssuer);
    const accessToken = await this.#getAccessToken(client, codeResponse, proofs, options);
    return client.userinfo(accessToken, options);
  }

  async token(codeResponse, expectedIssuer, proofs, options = {}) {
    const client = await this.#getClient(expectedIssuer);
    return this.#getAccessToken(client, codeResponse, proofs, options);
  }

  async refreshToken(expectedIssuer, refreshToken, options = {}) {
    const client = await this.#getClient(expectedIssuer);
    return client.refresh(refreshToken, options);
  }

  async userInfo(expectedIssuer, accessToken, options = {}) {
    const client = await this.#getClient(expectedIssuer);
    return client.userinfo(accessToken, options);
  }

  // The unused params below were added to a) be consistent with the interface exposed by the
  // `userInfo` function, and, b) to be able to modify the underlying implementation to make
  // make a request to the OP without changing the interface of the function.
  async basicUserInfo(_expectedIssuer, accessToken, _options = {}) {
    return accessToken.claims();
  }

  async paymentDetailsInfo(expectedIssuer, accessToken, options = {}) {
    const client = await this.#getClient(expectedIssuer);
    const mTLS = !!client.tls_client_certificate_bound_access_tokens;

    let targetURL = client.issuer.payment_details_info_endpoint;
    if (mTLS && client.issuer.mtls_endpoint_aliases) {
      targetURL = client.issuer.mtls_endpoint_aliases.payment_details_info_endpoint;
    }
    if (!targetURL) {
      throw new Error(`Payment details is disabled in the OP`);
    }

    const response = await client.requestResource(targetURL, accessToken, options);
    const status = response.statusCode;
    if (status >= 400 && status < 600) {
      throw new Error(`Failed to get the bank accounts info. Data: ${response.body}, Status: ${status}`);
    }
    return JSON.parse(response.body);
  }

  async paymentProcessing(expectedIssuer, accessToken, options = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ amount: 0 }) }) {
    const client = await this.#getClient(expectedIssuer);
    const mTLS = !!client.tls_client_certificate_bound_access_tokens;

    let targetURL = client.issuer.payment_processing_endpoint;
    if (mTLS && client.issuer.mtls_endpoint_aliases) {
      targetURL = client.issuer.mtls_endpoint_aliases.payment_processing_endpoint;
    }
    if (!targetURL) {
      throw new Error(`Payment processing is disabled in the OP`);
    }

    // Make a POST request with JSON as content type
    options.method = 'POST';
    options.headers = { ...options.headers, 'Content-Type': 'application/json' };

    const response = await client.requestResource(targetURL, accessToken, options);
    const status = response.statusCode;
    if (status >= 400 && status < 600) {
      throw new Error(`Failed to execute payment processing. Data: ${response.body}, Status: ${status}`);
    }
    return JSON.parse(response.body);
  }

  async credential(expectedIssuer, accessToken, body) {
    const httpClient = createHttpClient(expectedIssuer);

    const { data, status } = await httpClient.get('/.well-known/openid-credential-issuer');
    if (status !== 200) {
      throw new Error(`Failed to get the verifiable credential issuer configuration. Status: ${status}`);
    }
    return httpClient.request({
      baseURL: data.credential_endpoint,
      method: 'post',
      data: body,
      headers: {
        Authorization: `Bearer ${accessToken.access_token}`,
      },
    });
  }
}

module.exports = IDPartner;
