const { v4: uuidv4 } = require('uuid');
const IDPartner = require('../lib/idpartner');
const client = require('openid-client');

jest.mock('openid-client');

const ISSUER = 'https://oidc-provider.com'
const ISSUER_AUTH_ENDPOINT = 'https://oidc-provider.com/auth'
const ISSUER_PAR_RESPONSE = { request_uri: `some:uri:${uuidv4()}`, expires_in: 60 };
const VISITOR_ID = 'visitor-123';
const REQUEST_OBJECT =
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

describe('id-partner', function () {
  const ipd = new IDPartner({
    jwks: JWKS,
    client_id: 'mXzJ0TJEbWQb2A8s1z6gq',
    callback: 'http://myapplication.com',
    oidc_proxy_service_url: ISSUER,
  });

  beforeEach(() => {
    const issuerMock = jest.spyOn(client, 'Issuer');
    const clientMock = jest.fn().mockReturnValue({
      issuer: { authorization_endpoint: ISSUER_AUTH_ENDPOINT},
      requestObject: () => REQUEST_OBJECT,
      pushedAuthorizationRequest: () => ISSUER_PAR_RESPONSE,
    });
    issuerMock.discover = () => Promise.resolve({ Client: clientMock });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
  describe('#getAuthorizationUrl', () => {
    test('returns a valid url', async () => {
      const proofs = ipd.generateProofs();
      const url = await ipd.getAuthorizationUrl({ iss: ISSUER, visitor_id: VISITOR_ID }, proofs, ['openid']);
      const queryParams = new URLSearchParams({ request_uri: ISSUER_PAR_RESPONSE.request_uri });
      expect(url).toBe(`${ISSUER_AUTH_ENDPOINT}?${queryParams.toString()}`);
    });

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
  });

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
});
