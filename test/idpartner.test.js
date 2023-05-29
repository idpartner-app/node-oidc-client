const { v4: uuidv4 } = require('uuid');
const IDPartner = require('../lib/idpartner');
const openidClient = require('openid-client');

jest.mock('openid-client');

const ACCOUNT_SELECTOR = 'https://account-selector.com';
const CLIENT_ID = 'mXzJ0TJEbWQb2A8s1z6gq';
const CALLBACK_URI = 'http://myapplication.com';
const VISITOR_ID = 'visitor-123';
const ISSUER = 'https://oidc-provider.com';
const ISSUER_AUTH_ENDPOINT = 'https://oidc-provider.com/auth';
const ISSUER_PAR_RESPONSE = { request_uri: `some:uri:${uuidv4()}`, expires_in: 60 };
const ISSUER_REQUEST_OBJECT =
  'eyJhbGciOiJQUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiIzZUxfTFNFZ0VIQ05hNDVtd1U3elo4M1NFSHZYMk1lc2RLV2NQMTRqUThzIn0.eyJyZWRpcmVjdF91cmkiOiJodHRwczovL3JwLmlkcGFydG5lci1kZXYuY29tL2J1dHRvbi9vYXV0aC9jYWxsYmFjayIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJjb2RlX2NoYWxsZW5nZSI6ImpTeUNkZkdiQkRuWVBqTmh5OGVxaFZ6bjBYRGtGRUpoUWVkU2poZ1NUUTQiLCJzdGF0ZSI6IjJiRm8tMGplZW1NTVRQWUs2TlE2X0hHY19HWEJxN2FWT0FhN2l3RlVrNEEiLCJub25jZSI6Ijc4ZWI4NTRhLTE4NjctNDhkZi05MThlLTY4OWFjN2Y3Zjc3YyIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJyZXNwb25zZV9tb2RlIjoiand0IiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJjbGllbnRfaWQiOiJEU0N6Y1h6QnZRWWNfM3lCeVhxMDIiLCJuYmYiOjE2NjUxODMyMTIsIngtZmFwaS1pbnRlcmFjdGlvbi1pZCI6ImY2YjI4NTYwLWM3NDQtNGQzYS05MGEyLTMzOTYxY2U1Yzg3MiIsImlzcyI6IkRTQ3pjWHpCdlFZY18zeUJ5WHEwMiIsImF1ZCI6Imh0dHBzOi8vYXV0aC1hcGkuaWRwYXJ0bmVyLWRldi5jb20vb2lkYyIsImp0aSI6IjNiT0lxaXNLTklLUFVvX1FZcFhIRm9hRnpZZUJzUlpHSE44OVBGTzJ1enMiLCJpYXQiOjE2NjUxODMyMTIsImV4cCI6MTY2NTE4MzUxMn0.J-jqQu5POpoog00Adzfib6D1rAvD5weKDqbA8pNCs3G4NwIiKG06sl35WKs9Zcr1TcdXvSKlRMqJvkqBP3SAWcBdUeB2b9SoO8PpYcHDQohIwZNrtCAQTECXhmly3_5PooAxPMij7mErmqMQVB8V6g_3Ljen8UcZQwgIQs5SVEpNmTwtkfOd7mhgxQlhENbYcc41aRbFyAz5of927bHlM_4t_ZBn6EDB05bTiw56UXl8IW1UdfcsgbQMkSCe-QfAFmL9BgsXHr5N2NRGu8w2WusejH-Hh-EUfVKEEmyTsFh_jyDRG-ZEF2pGWUFoobW2nQ3yArOv5yuRD6-uHIJa_w';
const JWKS = {
  keys: [
    {
      p: 'uupd5cROId24eQ3SqTDXQoXYZrdvQSMQ7ZGwyECf_9loThSs3c3hdvMQXnqzb7i-Zv60pMpaAi3s9DgHZZnPRUt5HgAYEfUAVF4aiLvkndhmeTRnI5D9WU_I9h6JlHo16nVwgqgwNglYnGigzDaTIeN7P3G3P9eA0tKkVhSTm0U',
      kty: 'RSA',
      q: 'tAzuMm8Mu6-UXnmxLKosHrq3wYyPz1vnIUlbj16I9UhU6Fed2_YMNrZZTvd1ajSccdC-BnZPZDpFaEL4oPd0rZHO70Wg_XUXKnKfZ_4MZ2aft9lem4vGAlaIVcME00E24HNS1gMfIor23AbfX9aq-jue0Sfdb-PjDbULaWPTcE0',
      d: 'OwrMqCKXBW248kbYdqxFezYZU68_KKBbxcf19uyiTSusTvqdfXec0OHL0r9uQTihK4k2GW2hxiUQ2iPYxarpYP-q9FL_bOohyPJl9FErbt07NnRPwx8hZAuqjZqR8Ay_5hqhkRXPAYaCNkbJZv1JhqzWWX2u8rXaVb7K2GzGVlJXNodxhkC2NgWhtECEYJz6FLXymr6NRd_nuOYO0QONqirGef4z-aZeYHZUqAc2glinyUqzLF4jgg2JqOs3unu58L924I1dCx_VtEGDz5gOVup3kRu0TnjXPbxxvlFY-JjyQd1XstowM2XiPamJEaV_XzLyNMAW6B7NepiYVnV-4Q',
      e: 'AQAB',
      use: 'sig',
      qi: 'kRs4FhjYyCiUpUmaDLczja8M00RdcG8mZEhSd5gQZ83MOefR7xyF8Qxbq15KF4-ov3vRHtqk8kxJSINhEwGIB8t3S8x4M0QkZChMlgkzj9h0r9Z_Pj2VK5HnVYQyj2MgOGZvlOSHMA8RFm8HvVMwjhqsBoAOPSTtg7xTi_NRiwo',
      dp: 'J4G57wKa8RWIFC4TxKcKGIlpv-wtm7rprQ0KLIlcSBuPrFE6aHdHnHirkQymOIr305UqYVpTw_opB0WAar0jziWxp-GlNMZwF2T8fsIYBDTlE-E7m4zdv67ZbwvtUHC0TKYd7b_W0NUQ4Z5Lvl4aoyMNvc8vSFMoa2cSTQ90U3E',
      alg: 'PS256',
      dq: 'etOnWzhuk0sACEM0HqgoWP4_hQYCxQ6I6ihFEdUH0Wx6n9XFltyPEHPtEPW3X7BsWShxua7UEie-WZX2TrkBG7cwWAJEBSPvncF8BVFF3PQhWSYsaCg9-DJX50mW7Ra7_PovNFgE0WfDZ-44TAUBtpsdiMmNQltP9XXgRxEWmLE',
      n: 'g3Y67KrzAZbi3RYzx8Be-KxRbGRthFGEBzL7alt5CBsUSb6rRTlELLo8Qq90Aw1CHogB1P9iXa22sPJNALXfTAHX7BUde8ckbyeZOFWUmsAXjMW6qMFUsDgRnVifbd8xX77wvgQSOVi6lYABguttJwCeI7HL7FnNIkuImE5V7DdWB4PT_iVqQ-jw32VLpVgvkd3sd9fSYfbw9f2tCi0jYdxAJ0ZpVI1dAlLzwlBcElQ870Rv_2PoEeR_2SGadLLGY87b0aYu67VcX9Oz44gKwFyl8YjFwjufncqWDzFEWbwaaSamVsCqS_dK9iKGSgH8FhOfopgKacVfKMfmbTLjwQ',
    },
  ],
};
const ISSUER_CODE_RESPONSE = 'gx83lI3qlXqzcJAOYUcU789QqIYEA0';
const ISSUER_BASIC_USERINFO_RESPONSE = {
  email: "john@idpartner.com",
  family_name: "John",
  given_name: "Doe",
};
const ISSUER_FULL_USERINFO_RESPONSE = {
  email: "john@idpartner.com",
  family_name: "John",
  given_name: "Doe",
  address: {
    street_address: '7572 CHOWNING RD',
    locality: 'SPRINGFIELD',
    region: 'TN',
    postal_code: '37172-6488',
  }
};
const ISSUER_TOKEN_RESPONSE = {
  access_token: 'Bw46G9pHPg3IRW5bAPDSRFPzD88jghkAcl4g2wSc0X-',
  refresh_token: 'HsdPir0TEi4TiiyUXa90sQGauOqUkmyJ4SDUGU8xL4cKlaf4BbHMO0c4uebs',
  expires_at: 1680738657,
  id_token: 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii1NXzl2cUppMHRTWURlWEZoM2Nsdlo3MG50Qm9zVVZUOWFxQi0tMlNRaVUifQ.eyJzdWIiOiJkMDQ5YTYxOC05OGU1LTQ5MjItYjkxOS1kNTU3MjEwOGE5NTIiLCJlbWFpbCI6IlBoaWxpcEhMb3ZldHRAbWlrb21vdGVzdC5jb20iLCJmYW1pbHlfbmFtZSI6IkxvdmV0dCIsImdpdmVuX25hbWUiOiJQaGlsaXAiLCJub25jZSI6IkRzc185UXdlLTk5bGU1NGlsaUtKUHhreTdkQm1TLVUtR3FQMEd6WDUxUVUiLCJhdF9oYXNoIjoiZ21rdGpTa0xIaUl4eWo2VHpPa2pTQSIsImF1ZCI6IjV0THJ4dEZTRTRqQXRQWXRkeUNRWSIsImV4cCI6MTY4MDczODY1NywiaWF0IjoxNjgwNzM4NTk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEifQ.HxtbBftvGhGutmS1pC-PGpYJU7eONOuRjumIwlkD3A5Y6yzyjdZWKgj7JoA8qIO2NPDtoYwFVDV5E4gAADiun3SMBQ2mE0_ho9mfGbuskv9BC6VWSt_Z6eJHrWq83fpJrRxJGS16nSdCFo-0f8l71fl2BZdTlINxkTadu5Sc01e0usXkAlQIhtAwvCzcg-4RA5VePVaEhG_8OGxG8hPcyEMYvYpKlQ3XcaVTBRADmB0ody58RpKrEiR1AJyeha99v2HI-oGC62DpyK04SsTEcEzied9BDlEpsygWyQSqWa2gRW5Oov2FXAy37zcdYqGLG0nILZbSIX3lVJttD839wA',
  scope: 'openid email profile address offline_access',
  token_type: 'Bearer',
  claims: jest.fn(),
};

describe('id-partner', function () {
  let issuerMock;
  let issuerDiscoverMockFn;
  let clientMockFn;
  let clientCallbackMockFn;

  const ipd = new IDPartner({
    jwks: JWKS,
    client_id: CLIENT_ID,
    callback: CALLBACK_URI,
    account_selector_service_url: ACCOUNT_SELECTOR,
  });

  beforeEach(() => {
    clientCallbackMockFn = jest.fn().mockReturnValue(ISSUER_TOKEN_RESPONSE);
    clientRefreshTokenMockFn = jest.fn().mockReturnValue(ISSUER_TOKEN_RESPONSE);
    clientBasicUserInfoMockFn = jest.fn().mockReturnValue(ISSUER_BASIC_USERINFO_RESPONSE);
    clientFullUserInfoMockFn = jest.fn().mockReturnValue(ISSUER_FULL_USERINFO_RESPONSE);
    clientRequestObjectMockFn = jest.fn().mockReturnValue(ISSUER_REQUEST_OBJECT);
    clientPushedAuthRequestMockFn = jest.fn().mockReturnValue(ISSUER_PAR_RESPONSE);
    clientMockFn = jest.fn().mockReturnValue({
      issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT },
      requestObject: clientRequestObjectMockFn,
      pushedAuthorizationRequest: clientPushedAuthRequestMockFn,
      callback: clientCallbackMockFn,
      refresh: clientRefreshTokenMockFn,
      userinfo: clientFullUserInfoMockFn,
      redirect_uris: [CALLBACK_URI],
    });

    issuerDiscoverMockFn = jest.fn().mockResolvedValue({ Client: clientMockFn });
    issuerMock = jest.spyOn(openidClient, 'Issuer');
    issuerMock.discover = issuerDiscoverMockFn;

    ISSUER_TOKEN_RESPONSE.claims = clientBasicUserInfoMockFn;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const assertIssuerDiscoveryAndClientInitialization = () => {
    // Validates that we call the correct underlying library function to fetch the issuer metadata
    expect(issuerDiscoverMockFn.mock.calls.length).toBe(1);
    expect(issuerDiscoverMockFn.mock.calls[0]).toEqual([ISSUER]);

    // Validates that we call the correct underlying library function to instantiate the client
    expect(clientMockFn.mock.calls.length).toBe(1);
    expect(clientMockFn.mock.calls[0]).toEqual([
      {
        client_id: CLIENT_ID,
        token_endpoint_auth_method: 'private_key_jwt',
        redirect_uris: [CALLBACK_URI],
        authorization_signed_response_alg: 'PS256',
        authorization_encrypted_response_alg: 'RSA-OAEP',
        authorization_encrypted_response_enc: 'A256CBC-HS512',
        id_token_signed_response_alg: 'PS256',
        id_token_encrypted_response_alg: 'RSA-OAEP',
        id_token_encrypted_response_enc: 'A256CBC-HS512',
        request_object_signing_alg: 'PS256',
      },
      JWKS,
    ]);
  };

  const assertRequestObjectCreationAndPushedAuthRequest = ({ proofs, consent }) => {
    // Validates that we call the correct underlying library function to get a request object
    expect(clientRequestObjectMockFn.mock.calls.length).toBe(1);
    expect(clientRequestObjectMockFn.mock.calls[0]).toMatchObject([{
      redirect_uri: CALLBACK_URI,
      code_challenge_method: 'S256',
      code_challenge: proofs.codeChallenge,
      state: proofs.state,
      nonce: proofs.nonce,
      scope: 'openid',
      prompt: consent,
      response_mode: 'jwt',
      response_type: 'code',
      client_id: CLIENT_ID,
      nbf: expect.any(Number),
      'x-fapi-interaction-id': expect.any(String),
      identity_provider_id: undefined,
      idpartner_token: undefined,
    }]);

    // Validates that we call the correct underlying library function to perform a PAR request
    expect(clientPushedAuthRequestMockFn.mock.calls.length).toBe(1);
    expect(clientPushedAuthRequestMockFn.mock.calls[0]).toEqual([{ request: ISSUER_REQUEST_OBJECT }]);
  };

  describe('#generateProofs', () => {
    test('generateProofs returns state, nonce and codeVerifier', async () => {
      const proofs = ipd.generateProofs();
      expect(proofs).toHaveProperty('state');
      expect(proofs).toHaveProperty('nonce');
      expect(proofs).toHaveProperty('codeVerifier');
    });
  });

  describe('#getPublicJWKs', () => {
    test('getPublicJWKs does not include private key', async () => {
      const jwks = await ipd.getPublicJWKs();
      expect(jwks.d).toBeUndefined();
    });
  });

  describe('#getAuthorizationUrl', () => {
    test('fails if scope is missing ', async () => {
      const proofs = ipd.generateProofs();
      expect(ipd.getAuthorizationUrl({ visitor_id: VISITOR_ID }, proofs)).rejects.toThrow();
    });

    test('fails if proofs is missing ', async () => {
      expect(ipd.getAuthorizationUrl({ visitor_id: VISITOR_ID })).rejects.toThrow();
    });

    test('fails if query is missing ', async () => {
      expect(ipd.getAuthorizationUrl()).rejects.toThrow();
    });

    test('calls the correct underlying library functions and returns a valid url', async () => {
      const consent = 'prompt';
      const proofs = ipd.generateProofs();
      const url = await ipd.getAuthorizationUrl({ iss: ISSUER, visitor_id: VISITOR_ID }, proofs, ['openid'], consent);

      // Validates that client is correctly initialized
      assertIssuerDiscoveryAndClientInitialization();

      // Validates that request object and PAR is made
      assertRequestObjectCreationAndPushedAuthRequest({ proofs, consent });

      // Validates the response is the url we expect
      const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
      expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
    });

    test('returns a valid url if consent is not specified', async () => {
      const proofs = ipd.generateProofs();
      const url = await ipd.getAuthorizationUrl({ iss: ISSUER, visitor_id: VISITOR_ID }, proofs, ['openid']);
      // Validates that client is correctly initialized
      assertIssuerDiscoveryAndClientInitialization();

      // Validates that request object and PAR is made
      assertRequestObjectCreationAndPushedAuthRequest({ proofs, consent: undefined });

      // Validates the response is the url we expect
      const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
      expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
    });
  });

  describe('#token', () => {
    test('calls the correct underlying library functions and returns an access token', async () => {
      const proofs = ipd.generateProofs();
      const token = await ipd.token(ISSUER_CODE_RESPONSE, ISSUER, proofs);

      // Validates that client is correctly initialized
      assertIssuerDiscoveryAndClientInitialization();

      // Validates that we call the correct underlying library function to get an access token
      expect(clientCallbackMockFn.mock.calls.length).toBe(1);
      expect(clientCallbackMockFn.mock.calls[0]).toEqual([
        CALLBACK_URI,
        { response: ISSUER_CODE_RESPONSE },
        { jarm: true, state: proofs.state, nonce: proofs.nonce, code_verifier: proofs.codeVerifier },
        {}
      ]);

      // Validates the response is the access token we expect
      expect(token).toEqual(ISSUER_TOKEN_RESPONSE);
    });
  });

  describe('#refreshToken', () => {
    test('calls the correct underlying library functions and returns an access token', async () => {
      const token = ISSUER_TOKEN_RESPONSE;
      const refreshedToken = await ipd.refreshToken(ISSUER, token.refresh_token);

      // Validates that client is correctly initialized
      assertIssuerDiscoveryAndClientInitialization();

      // Validates that we call the correct underlying library function to get an access token
      expect(clientRefreshTokenMockFn.mock.calls.length).toBe(1);
      expect(clientRefreshTokenMockFn.mock.calls[0]).toEqual([token.refresh_token, {}]);

      // Validates the response is the access token we expect
      expect(refreshedToken).toEqual(ISSUER_TOKEN_RESPONSE);
    });
  });

  describe('#basicUserInfo', () => {
    test('calls the correct underlying library functions and returns basic user info', async () => {
      const token = ISSUER_TOKEN_RESPONSE;
      const basicUserInfo = await ipd.basicUserInfo(ISSUER, token);

      // Validates that we call the correct underlying library function to get an access token
      expect(clientBasicUserInfoMockFn.mock.calls.length).toBe(1);
      expect(clientBasicUserInfoMockFn.mock.calls[0]).toEqual([]);

      // Validates the response is the access token we expect
      expect(basicUserInfo).toEqual(ISSUER_BASIC_USERINFO_RESPONSE);
    });
  });

  describe('#userInfo', () => {
    test('calls the correct underlying library functions and returns full user info', async () => {
      const token = ISSUER_TOKEN_RESPONSE;
      const userinfo = await ipd.userInfo(ISSUER, token);

      // Validates that client is correctly initialized
      assertIssuerDiscoveryAndClientInitialization();

      // Validates that we call the correct underlying library function to get an access token
      expect(clientFullUserInfoMockFn.mock.calls.length).toBe(1);
      expect(clientFullUserInfoMockFn.mock.calls[0]).toEqual([token, {}]);

      // Validates the response is the access token we expect
      expect(userinfo).toEqual(ISSUER_FULL_USERINFO_RESPONSE);
    });
  });
});
