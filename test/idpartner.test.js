const { v4: uuidv4 } = require('uuid');
const IDPartner = require('../lib/idpartner');
const openidClient = require('openid-client');
const {
  ISSUER_PAYMENT_PROCESSING_RESPONSE,
  ISSUER_REQUEST_OBJECT,
  ISSUER_CODE_RESPONSE,
  ISSUER_BASIC_USERINFO_RESPONSE,
  ISSUER_FULL_USERINFO_RESPONSE,
  ISSUER_TOKEN_RESPONSE,
  JWKS,
  CLAIMS,
  ISSUER_PAR_RESPONSE,
  ISSUER_REFRESH_TOKEN_RESPONSE,
} = require('./fixtures');

jest.mock('openid-client');

const ACCOUNT_SELECTOR = 'https://account-selector.com';
const CLIENT_ID = 'mXzJ0TJEbWQb2A8s1z6gq';
const CLIENT_SECRET = uuidv4();
const CALLBACK_URI = 'http://myapplication.com';
const VISITOR_ID = 'visitor-123';
const ISSUER = 'https://oidc-provider.com';
const ISSUER_AUTH_ENDPOINT = 'https://oidc-provider.com/auth';
const ISSUER_PAYMENT_PROCESSING_ENDPOINT = 'https://oidc-provider.com/payment_processing';
const ISSUER_OBJ = {
  authorization_endpoint: ISSUER_AUTH_ENDPOINT,
};

const idpartnerPrivateKeyJwtConfig = {
  client_id: CLIENT_ID,
  callback: CALLBACK_URI,
  account_selector_service_url: ACCOUNT_SELECTOR,
  token_endpoint_auth_method: 'private_key_jwt',
  jwks: JWKS,
};

const idpartnerClientSecretConfig = {
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,
  callback: CALLBACK_URI,
  account_selector_service_url: ACCOUNT_SELECTOR,
  token_endpoint_auth_method: 'client_secret_basic',
};

const idpartnerClientSecretConfigWithJWKS = {
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,
  callback: CALLBACK_URI,
  account_selector_service_url: ACCOUNT_SELECTOR,
  token_endpoint_auth_method: 'client_secret_basic',
  jwks: JWKS,
};

const idpartnerClientMTLSConfig = {
  client_id: CLIENT_ID,
  callback: CALLBACK_URI,
  account_selector_service_url: ACCOUNT_SELECTOR,
  token_endpoint_auth_method: 'tls_client_auth',
};

const idpartnerClientMTLSConfigWithJWKS = {
  client_id: CLIENT_ID,
  callback: CALLBACK_URI,
  account_selector_service_url: ACCOUNT_SELECTOR,
  token_endpoint_auth_method: 'tls_client_auth',
  jwks: JWKS,
};

describe('idpartner', function () {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  const getIdpartnerClient = ({ clientConfig = {}, customUnderlyingClientBehavior = {} }) => {
    // Initialize the underlying client with default and custom behavior
    const defaultUnderlyingClientBehavior = {
      issuer: ISSUER_OBJ,
      redirect_uris: [CALLBACK_URI],
      requestObject: jest.fn().mockReturnValue(ISSUER_REQUEST_OBJECT),
      pushedAuthorizationRequest: jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE),
      callback: jest.fn().mockReturnValue(ISSUER_TOKEN_RESPONSE),
      refresh: jest.fn().mockReturnValue(ISSUER_TOKEN_RESPONSE),
      userinfo: jest.fn().mockReturnValue(ISSUER_FULL_USERINFO_RESPONSE),
      callbackParams: jest.fn().mockReturnValue({ response: ISSUER_CODE_RESPONSE }),
    };

    const underlyingClientMock = jest.fn().mockReturnValue({
      ...defaultUnderlyingClientBehavior,
      ...customUnderlyingClientBehavior,
    });

    // Mock discover endpoint to always return the recently created underlying client
    const issuerDiscoverMockFn = jest.fn().mockResolvedValue({ Client: underlyingClientMock });
    const issuerMock = jest.spyOn(openidClient, 'Issuer');
    issuerMock.discover = issuerDiscoverMockFn;

    // Initialize the IDPartner client
    const idpartnerClient = new IDPartner(clientConfig);

    // Finally, return the client
    return { idpartnerClient, underlyingClientMock };
  };

  const assertUnderlyingClientInitialization = ({ clientConfig, underlyingClientMock }) => {
    const expectedUnderlyingClientInitializationParams = {
      client_id: clientConfig.client_id,
      token_endpoint_auth_method: clientConfig.token_endpoint_auth_method,
      redirect_uris: [clientConfig.callback],
      authorization_signed_response_alg: 'PS256',
      id_token_signed_response_alg: 'PS256',
    };

    if (clientConfig.token_endpoint_auth_method === 'client_secret_basic') {
      expectedUnderlyingClientInitializationParams['client_secret'] = clientConfig.client_secret;
    }

    if (clientConfig.token_endpoint_auth_method === 'tls_client_auth') {
      expectedUnderlyingClientInitializationParams['tls_client_certificate_bound_access_tokens'] = true;
    }

    if (clientConfig.jwks) {
      expectedUnderlyingClientInitializationParams['authorization_encrypted_response_alg'] = 'RSA-OAEP';
      expectedUnderlyingClientInitializationParams['authorization_encrypted_response_enc'] = 'A256CBC-HS512';
      expectedUnderlyingClientInitializationParams['id_token_encrypted_response_alg'] = 'RSA-OAEP';
      expectedUnderlyingClientInitializationParams['id_token_encrypted_response_enc'] = 'A256CBC-HS512';
      expectedUnderlyingClientInitializationParams['request_object_signing_alg'] = 'PS256';
    }

    // Validates that the underlying client instance was instantiated with the expected params
    expect(underlyingClientMock.mock.calls.length).toBe(1);
    expect(underlyingClientMock.mock.calls[0]).toEqual([expectedUnderlyingClientInitializationParams, clientConfig.jwks]);
  };

  const assertUnderlyingClientRequestObjectCreationAndPushedAuthRequest = ({ clientConfig, underlyingClientMock, proofs, prompt, claims }) => {
    const { requestObject: requestObjectMock, pushedAuthorizationRequest: pushedAuthorizationRequestMock } = underlyingClientMock.mock.results[0].value;

    const expectedRequestParams = {
      redirect_uri: clientConfig.callback,
      code_challenge_method: 'S256',
      code_challenge: proofs.codeChallenge,
      state: proofs.state,
      nonce: proofs.nonce,
      scope: 'openid',
      prompt,
      response_mode: 'jwt',
      response_type: 'code',
      client_id: clientConfig.client_id,
      nbf: expect.any(Number),
      'x-fapi-interaction-id': expect.any(String),
      identity_provider_id: undefined,
      idpartner_token: undefined,
      ...(claims ? { claims: JSON.stringify(claims) } : undefined),
    };

    if (clientConfig.jwks) {
      // Validates that we call the correct underlying function to build a request object
      expect(requestObjectMock.mock.calls.length).toBe(1);
      expect(requestObjectMock.mock.calls[0]).toMatchObject([expectedRequestParams]);

      // Validates that we call the correct underlying function with the expected requested object to perform a PAR request
      expect(pushedAuthorizationRequestMock.mock.calls.length).toBe(1);
      expect(pushedAuthorizationRequestMock.mock.calls[0]).toEqual([{ request: ISSUER_REQUEST_OBJECT }]);
    } else {
      // Validates that no request object call is made if JWKS are not set
      expect(requestObjectMock.mock.calls.length).toBe(0);

      // Validates that we call the correct underlying function with the expected raw params (no request object) to perform a PAR request
      expect(pushedAuthorizationRequestMock.mock.calls.length).toBe(1);
      expect(pushedAuthorizationRequestMock.mock.calls[0]).toEqual([expectedRequestParams]);
    }
  };

  describe('#generateProofs', () => {
    test('generateProofs returns state, nonce and codeVerifier', async () => {
      const { idpartnerClient } = getIdpartnerClient({ clientConfig: idpartnerClientSecretConfig });
      const proofs = idpartnerClient.generateProofs();
      expect(proofs).toHaveProperty('state');
      expect(proofs).toHaveProperty('nonce');
      expect(proofs).toHaveProperty('codeVerifier');
    });
  });

  describe('#getPublicJWKs', () => {
    test('client without JWKS - return empty object', async () => {
      const { idpartnerClient } = getIdpartnerClient({ clientConfig: idpartnerClientSecretConfig });
      const jwks = await idpartnerClient.getPublicJWKs();
      expect(jwks).toEqual({});
    });

    test('client with JWKS - return public but not private claims', async () => {
      const { idpartnerClient } = getIdpartnerClient({ clientConfig: idpartnerClientSecretConfigWithJWKS });
      const jwks = await idpartnerClient.getPublicJWKs();
      expect(jwks).not.toEqual({});
      expect(jwks.d).toBeUndefined();
    });
  });

  for (const clientConfig of [idpartnerPrivateKeyJwtConfig, idpartnerClientSecretConfig, idpartnerClientSecretConfigWithJWKS, idpartnerClientMTLSConfig, idpartnerClientMTLSConfigWithJWKS]) {
    const testPrefix = `${clientConfig.token_endpoint_auth_method} - ${clientConfig.jwks ? 'with JWKS' : 'no JWKS'}`;

    describe('#getAuthorizationUrl', () => {
      test(`${testPrefix} - fails if scope is missing`, async () => {
        const { idpartnerClient } = getIdpartnerClient({ clientConfig });
        const proofs = idpartnerClient.generateProofs();
        expect(idpartnerClient.getAuthorizationUrl({ visitor_id: VISITOR_ID }, proofs)).rejects.toThrow();
      });

      test(`${testPrefix} - fails if proofs is missing`, async () => {
        const { idpartnerClient } = getIdpartnerClient({ clientConfig });
        expect(idpartnerClient.getAuthorizationUrl({ visitor_id: VISITOR_ID })).rejects.toThrow();
      });

      test(`${testPrefix} - fails if query is missing`, async () => {
        const { idpartnerClient } = getIdpartnerClient({ clientConfig });
        expect(idpartnerClient.getAuthorizationUrl()).rejects.toThrow();
      });

      test(`${testPrefix} - calls the correct underlying library functions and returns a valid url`, async () => {
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig,
          customUnderlyingClientBehavior: {
            issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT },
            pushedAuthorizationRequest: jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE),
          },
        });
        const prompt = 'consent';
        const proofs = idpartnerClient.generateProofs();
        const query = { iss: ISSUER, visitor_id: VISITOR_ID };
        const extraAuthorizationParams = { prompt };
        const url = await idpartnerClient.getAuthorizationUrl(query, proofs, ['openid'], extraAuthorizationParams);

        // Validates that the underlying client was correctly initialized
        assertUnderlyingClientInitialization({ clientConfig, underlyingClientMock });

        // Validates that request object and PAR is made
        assertUnderlyingClientRequestObjectCreationAndPushedAuthRequest({ clientConfig, underlyingClientMock, proofs, prompt });

        // Validates the response is the url we expect
        const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
        expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
      });

      test(`${testPrefix} - returns a valid url if prompt is not specified`, async () => {
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT },
            pushedAuthorizationRequest: jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE),
          },
        });
        const proofs = idpartnerClient.generateProofs();
        const query = { iss: ISSUER, visitor_id: VISITOR_ID };
        const url = await idpartnerClient.getAuthorizationUrl(query, proofs, ['openid']);

        // Validates that the underlying client was correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that request object and PAR is made
        assertUnderlyingClientRequestObjectCreationAndPushedAuthRequest({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock, proofs, prompt: undefined });

        // Validates the response is the url we expect
        const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
        expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
      });

      test(`${testPrefix} - calls the correct underlying library functions and returns a valid url when claims parameter is used`, async () => {
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT },
            pushedAuthorizationRequest: jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE),
          },
        });
        const prompt = 'consent';
        const proofs = idpartnerClient.generateProofs();
        const query = { iss: ISSUER, visitor_id: VISITOR_ID };
        const extraAuthorizationParams = { prompt, claims: CLAIMS };
        const url = await idpartnerClient.getAuthorizationUrl(query, proofs, ['openid'], extraAuthorizationParams);

        // Validates that the underlying client was correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that request object and PAR is made
        assertUnderlyingClientRequestObjectCreationAndPushedAuthRequest({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock, proofs, prompt, claims: CLAIMS });

        // Validates the response is the url we expect
        const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
        expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
      });

      test(`${testPrefix} - calls the correct underlying library functions and returns a valid url when claims parameter is undefined`, async () => {
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT },
            pushedAuthorizationRequest: jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE),
          },
        });
        const prompt = 'consent';
        const claims = undefined;
        const proofs = idpartnerClient.generateProofs();
        const query = { iss: ISSUER, visitor_id: VISITOR_ID };
        const extraAuthorizationParams = { prompt, claims };
        const url = await idpartnerClient.getAuthorizationUrl(query, proofs, ['openid'], extraAuthorizationParams);

        // Validates that the underlying client was correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that request object and PAR is made
        assertUnderlyingClientRequestObjectCreationAndPushedAuthRequest({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock, proofs, prompt, claims });

        // Validates the response is the url we expect
        const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
        expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
      });

      test(`${testPrefix} - returns the converted claims into scopes when claims parameter is used`, async () => {
        const { idpartnerClient } = getIdpartnerClient({ clientConfig: idpartnerClientSecretConfig });
        const prompt = 'consent';
        const proofs = idpartnerClient.generateProofs();
        const query = { visitor_id: VISITOR_ID };
        const extraAuthorizationParams = { prompt, claims: CLAIMS };
        const url = await idpartnerClient.getAuthorizationUrl(query, proofs, ['openid'], extraAuthorizationParams);

        // Validates the response is the url we expect
        expect(url).toBe(
          `${idpartnerClientSecretConfig.account_selector_service_url}/auth/select-accounts?client_id=${idpartnerClientSecretConfig.client_id}&visitor_id=${VISITOR_ID}&scope=openid&claims=payment_details email`,
        );
      });
    });

    describe('#token', () => {
      test(`${testPrefix} - calls the correct underlying library functions and returns an access token`, async () => {
        const callbackMockFn = jest.fn().mockReturnValue(ISSUER_TOKEN_RESPONSE);
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            callback: callbackMockFn,
          },
        });
        const proofs = idpartnerClient.generateProofs();
        const token = await idpartnerClient.token(ISSUER_CODE_RESPONSE, ISSUER, proofs);

        // Validates that client is correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that we call the correct underlying library function to get an access token
        expect(callbackMockFn.mock.calls.length).toBe(1);
        expect(callbackMockFn.mock.calls[0]).toEqual([
          idpartnerClientSecretConfig.callback,
          { response: ISSUER_CODE_RESPONSE },
          {
            state: proofs.state,
            nonce: proofs.nonce,
            code_verifier: proofs.codeVerifier,
          },
          {},
        ]);

        // Validates the response is the access token we expect
        expect(token).toEqual(ISSUER_TOKEN_RESPONSE);
      });
    });

    describe('#refreshToken', () => {
      test(`${testPrefix} - calls the correct underlying library functions and returns a refresh token`, async () => {
        const refreshTokenMockFn = jest.fn().mockReturnValue(ISSUER_REFRESH_TOKEN_RESPONSE);
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            refresh: refreshTokenMockFn,
          },
        });

        const refreshedToken = await idpartnerClient.refreshToken(ISSUER, ISSUER_TOKEN_RESPONSE.refresh_token);

        // Validates that client is correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that we call the correct underlying library function to get an access token
        expect(refreshTokenMockFn.mock.calls.length).toBe(1);
        expect(refreshTokenMockFn.mock.calls[0]).toEqual([ISSUER_TOKEN_RESPONSE.refresh_token, {}]);

        // Validates the response is the access token we expect
        expect(refreshedToken).toEqual(ISSUER_REFRESH_TOKEN_RESPONSE);
      });
    });

    describe('#basicUserInfo', () => {
      test(`${testPrefix} - calls the correct underlying library functions and returns basic user info`, async () => {
        const basicUserInfoMockFn = jest.fn().mockReturnValue(ISSUER_BASIC_USERINFO_RESPONSE);
        const { idpartnerClient } = getIdpartnerClient({ clientConfig: idpartnerClientSecretConfig });

        const token = { ...ISSUER_TOKEN_RESPONSE, claims: basicUserInfoMockFn };
        const basicUserInfo = await idpartnerClient.basicUserInfo(ISSUER, token);

        // Validates that we call the correct underlying library function to get an access token
        expect(basicUserInfoMockFn.mock.calls.length).toBe(1);
        expect(basicUserInfoMockFn.mock.calls[0]).toEqual([]);

        // Validates the response is the access token we expect
        expect(basicUserInfo).toEqual(ISSUER_BASIC_USERINFO_RESPONSE);
      });
    });

    describe('#userInfo', () => {
      test(`${testPrefix} - calls the correct underlying library functions and returns full user info`, async () => {
        const fullUserInfoMockFn = jest.fn().mockReturnValue(ISSUER_FULL_USERINFO_RESPONSE);
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            userinfo: fullUserInfoMockFn,
          },
        });

        const token = ISSUER_TOKEN_RESPONSE;
        const userinfo = await idpartnerClient.userInfo(ISSUER, token);

        // Validates that client is correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that we call the correct underlying library function to get an access token
        expect(fullUserInfoMockFn.mock.calls.length).toBe(1);
        expect(fullUserInfoMockFn.mock.calls[0]).toEqual([token, {}]);

        // Validates the response is the access token we expect
        expect(userinfo).toEqual(ISSUER_FULL_USERINFO_RESPONSE);
      });
    });

    describe('#paymentProcessing', () => {
      test(`${testPrefix} - raises error if payment processing is disabled in the OP`, async () => {
        const { idpartnerClient } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: {
              authorization_endpoint: ISSUER_AUTH_ENDPOINT,
              payment_processing_endponit: undefined,
            },
          },
        });

        expect(idpartnerClient.paymentProcessing(ISSUER, ISSUER_TOKEN_RESPONSE, { body: JSON.stringify({ amount: 100 }) })).rejects.toThrow();
      });

      test(`${testPrefix} - raises error if payment processing fails at the OP`, async () => {
        const requestResourceMockFn = jest.fn().mockReturnValue({ statusCode: 400, body: JSON.stringify({ error: 'failed' }) });

        const { idpartnerClient } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: {
              authorization_endpoint: ISSUER_AUTH_ENDPOINT,
              payment_processing_endpoint: ISSUER_PAYMENT_PROCESSING_ENDPOINT,
            },
            requestResource: requestResourceMockFn,
          },
        });

        expect(idpartnerClient.paymentProcessing(ISSUER, ISSUER_TOKEN_RESPONSE, { body: JSON.stringify({ amount: 100 }) })).rejects.toThrow();
      });

      test(`${testPrefix} - calls the correct underlying library functions and returns payment processing data`, async () => {
        const requestResourceMockFn = jest.fn().mockReturnValue({ statusCode: 200, body: JSON.stringify(ISSUER_PAYMENT_PROCESSING_RESPONSE) });
        const { idpartnerClient, underlyingClientMock } = getIdpartnerClient({
          clientConfig: idpartnerClientSecretConfig,
          customUnderlyingClientBehavior: {
            issuer: {
              authorization_endpoint: ISSUER_AUTH_ENDPOINT,
              payment_processing_endpoint: ISSUER_PAYMENT_PROCESSING_ENDPOINT,
            },
            requestResource: requestResourceMockFn,
          },
        });

        const requestBody = JSON.stringify({ amount: 100 });
        const paymentResponse = await idpartnerClient.paymentProcessing(ISSUER, ISSUER_TOKEN_RESPONSE, { body: requestBody });

        // Validates that client is correctly initialized
        assertUnderlyingClientInitialization({ clientConfig: idpartnerClientSecretConfig, underlyingClientMock });

        // Validates that we call the correct underlying library function to perform payment processing
        expect(requestResourceMockFn.mock.calls.length).toBe(1);
        expect(requestResourceMockFn.mock.calls[0]).toEqual([
          ISSUER_PAYMENT_PROCESSING_ENDPOINT,
          ISSUER_TOKEN_RESPONSE,
          {
            body: requestBody,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
          },
        ]);

        // Validates the response is the mocked payment processing response
        expect(paymentResponse).toEqual(ISSUER_PAYMENT_PROCESSING_RESPONSE);
      });
    });
  }
});
