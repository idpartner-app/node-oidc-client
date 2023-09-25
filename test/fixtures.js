const { v4: uuidv4 } = require('uuid');

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
  email: 'john@idpartner.com',
  family_name: 'John',
  given_name: 'Doe',
};

const ISSUER_FULL_USERINFO_RESPONSE = {
  email: 'john@idpartner.com',
  family_name: 'John',
  given_name: 'Doe',
  address: {
    street_address: '7572 CHOWNING RD',
    locality: 'SPRINGFIELD',
    region: 'TN',
    postal_code: '37172-6488',
  },
};

const ISSUER_TOKEN_RESPONSE = {
  access_token: 'Bw46G9pHPg3IRW5bAPDSRFPzD88jghkAcl4g2wSc0X-',
  refresh_token: 'HsdPir0TEi4TiiyUXa90sQGauOqUkmyJ4SDUGU8xL4cKlaf4BbHMO0c4uebs',
  expires_at: 1680738657,
  id_token:
    'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii1NXzl2cUppMHRTWURlWEZoM2Nsdlo3MG50Qm9zVVZUOWFxQi0tMlNRaVUifQ.eyJzdWIiOiJkMDQ5YTYxOC05OGU1LTQ5MjItYjkxOS1kNTU3MjEwOGE5NTIiLCJlbWFpbCI6IlBoaWxpcEhMb3ZldHRAbWlrb21vdGVzdC5jb20iLCJmYW1pbHlfbmFtZSI6IkxvdmV0dCIsImdpdmVuX25hbWUiOiJQaGlsaXAiLCJub25jZSI6IkRzc185UXdlLTk5bGU1NGlsaUtKUHhreTdkQm1TLVUtR3FQMEd6WDUxUVUiLCJhdF9oYXNoIjoiZ21rdGpTa0xIaUl4eWo2VHpPa2pTQSIsImF1ZCI6IjV0THJ4dEZTRTRqQXRQWXRkeUNRWSIsImV4cCI6MTY4MDczODY1NywiaWF0IjoxNjgwNzM4NTk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEifQ.HxtbBftvGhGutmS1pC-PGpYJU7eONOuRjumIwlkD3A5Y6yzyjdZWKgj7JoA8qIO2NPDtoYwFVDV5E4gAADiun3SMBQ2mE0_ho9mfGbuskv9BC6VWSt_Z6eJHrWq83fpJrRxJGS16nSdCFo-0f8l71fl2BZdTlINxkTadu5Sc01e0usXkAlQIhtAwvCzcg-4RA5VePVaEhG_8OGxG8hPcyEMYvYpKlQ3XcaVTBRADmB0ody58RpKrEiR1AJyeha99v2HI-oGC62DpyK04SsTEcEzied9BDlEpsygWyQSqWa2gRW5Oov2FXAy37zcdYqGLG0nILZbSIX3lVJttD839wA',
  scope: 'openid email profile address offline_access',
  token_type: 'Bearer',
  claims: jest.fn(),
};

const ISSUER_PAYMENT_PROCESSING_RESPONSE = {
  transaction_id: uuidv4(),
  account_statement_descriptor: uuidv4(),
  amount: 100,
  currency: 'USD',
};

const CLAIMS = {
  id_token: {
    email: {
      essential: true,
    },
  },
  userinfo: {
    payment_details: null,
  },
};

const ISSUER_PAR_RESPONSE = {
  request_uri: `some:uri:${uuidv4()}`,
  expires_in: 60,
};

module.exports = {
  ISSUER_PAYMENT_PROCESSING_RESPONSE,
  ISSUER_REQUEST_OBJECT,
  ISSUER_CODE_RESPONSE,
  ISSUER_BASIC_USERINFO_RESPONSE,
  ISSUER_FULL_USERINFO_RESPONSE,
  ISSUER_TOKEN_RESPONSE,
  ISSUER_REFRESH_TOKEN_RESPONSE: ISSUER_TOKEN_RESPONSE,
  JWKS,
  CLAIMS,
  ISSUER_PAR_RESPONSE,
};
