const axios = require('axios');
const IDPartner = require('../lib/idpartner');
const client = require('openid-client');

jest.mock('openid-client');
jest.mock('axios');

const REQUEST_JWT =
  'eyJhbGciOiJQUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiIzZUxfTFNFZ0VIQ05hNDVtd1U3elo4M1NFSHZYMk1lc2RLV2NQMTRqUThzIn0.eyJyZWRpcmVjdF91cmkiOiJodHRwczovL3JwLmlkcGFydG5lci1kZXYuY29tL2J1dHRvbi9vYXV0aC9jYWxsYmFjayIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJjb2RlX2NoYWxsZW5nZSI6ImpTeUNkZkdiQkRuWVBqTmh5OGVxaFZ6bjBYRGtGRUpoUWVkU2poZ1NUUTQiLCJzdGF0ZSI6IjJiRm8tMGplZW1NTVRQWUs2TlE2X0hHY19HWEJxN2FWT0FhN2l3RlVrNEEiLCJub25jZSI6Ijc4ZWI4NTRhLTE4NjctNDhkZi05MThlLTY4OWFjN2Y3Zjc3YyIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJyZXNwb25zZV9tb2RlIjoiand0IiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJjbGllbnRfaWQiOiJEU0N6Y1h6QnZRWWNfM3lCeVhxMDIiLCJuYmYiOjE2NjUxODMyMTIsIngtZmFwaS1pbnRlcmFjdGlvbi1pZCI6ImY2YjI4NTYwLWM3NDQtNGQzYS05MGEyLTMzOTYxY2U1Yzg3MiIsImlzcyI6IkRTQ3pjWHpCdlFZY18zeUJ5WHEwMiIsImF1ZCI6Imh0dHBzOi8vYXV0aC1hcGkuaWRwYXJ0bmVyLWRldi5jb20vb2lkYyIsImp0aSI6IjNiT0lxaXNLTklLUFVvX1FZcFhIRm9hRnpZZUJzUlpHSE44OVBGTzJ1enMiLCJpYXQiOjE2NjUxODMyMTIsImV4cCI6MTY2NTE4MzUxMn0.J-jqQu5POpoog00Adzfib6D1rAvD5weKDqbA8pNCs3G4NwIiKG06sl35WKs9Zcr1TcdXvSKlRMqJvkqBP3SAWcBdUeB2b9SoO8PpYcHDQohIwZNrtCAQTECXhmly3_5PooAxPMij7mErmqMQVB8V6g_3Ljen8UcZQwgIQs5SVEpNmTwtkfOd7mhgxQlhENbYcc41aRbFyAz5of927bHlM_4t_ZBn6EDB05bTiw56UXl8IW1UdfcsgbQMkSCe-QfAFmL9BgsXHr5N2NRGu8w2WusejH-Hh-EUfVKEEmyTsFh_jyDRG-ZEF2pGWUFoobW2nQ3yArOv5yuRD6-uHIJa_w';
const VISITOR_ID = 'visitor-123';
const OIDC_PROXY_SERVICE_URL = 'https://oidc-proxy.com';
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
    oidc_proxy_service_url: OIDC_PROXY_SERVICE_URL,
  });

  const success = {
    authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
    issuer: 'https://op.example.com',
    jwks_uri: 'https://op.example.com/oauth2/v3/certs',
    token_endpoint: 'https://op.example.com/oauth2/v4/token',
    userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
  };
  beforeEach(() => {
    const issuerMock = jest.spyOn(client, 'Issuer');
    const clientMock = jest.fn().mockReturnValue({ requestObject: () => REQUEST_JWT });
    issuerMock.discover = () => Promise.resolve({ Client: clientMock });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
  describe('#getAuthorizationUrl', () => {
    test('returns a valid url', async () => {
      const proofs = ipd.generateProofs();
      const url = await ipd.getAuthorizationUrl({ visitor_id: VISITOR_ID }, proofs, ['openid']);
      expect(url).toBe(`${OIDC_PROXY_SERVICE_URL}/auth?request=${REQUEST_JWT}&visitor_id=${VISITOR_ID}`);
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

  describe('#unpackProxyResponse', () => {
    beforeEach(() => {
      axios.get.mockResolvedValueOnce({ data: TRUST_DIRECTORY_JWKS });
    });
    const TRUST_DIRECTORY_JWKS = {
      keys: [
        {
          kty: 'RSA',
          kid: 'bAw7WVrf_P6l8n4B_cTMcKoEkRpQ_RcjPp0zKfsbBo0',
          use: 'sig',
          alg: 'PS256',
          e: 'AQAB',
          n: 'mmIHAPRKz9J4AZ-Ozz4LNhCfOak7E8s7kj019a9irk5c7cMRxEcRtZkaIBbdo3j9Hmer8_7EBahENL75XlG8XJwg96FwNJK58ov-mCIHDLCDZJGSL8gqaxYeyzyRG7dUwcRX_DA2st3n0_-3lhdARlXiEfAvdGBhd_fXzy_b4qOIQOQljxduLSCkRljJnOTZoMCscFAoS96L9-oi-JDgGMHmJMbunvTpfblnaicfwNfd_gbwsT4Ux9RXySBbiFOyTGh3aVYshLrTmtLd6axOgKtgXKMCsm4PDaPbtZ54B8bch-MDSowv0r8zqMlJo4IN8v2BP-a8sCva0nnckP-QwQ',
          d: 'KsdfCXSoBk5b0pdUCzk2AhU5CdFK_YEjULKFcT7YKVSti3SyR6Ep1xhFlP7BC7tK6FHx4_qEdszZmYQRtYEQoNjiibvCS88cl4kTUzSan3mJ7yQnTfY5StMmVUrDKtryMX8mokr53TaANs51ILHwrYy-yBm2DJloaMXUlyS72WDpAc4JXBceV0BSnu0fkM3clPYFmVVEHHqNRf3KC_gJFCWMAqlkkVes_hBj2962uq5OFnmTGY1IXyF2VTLtQ3ZkvtU1htJTeULKE3Xg1voxpc70b5PeUpNtDjQGfPkCwkzFCUnE8WPH6AyKrx-p8u7zPr6LqGQa35Mb1vQsnBzQAQ',
          p: 'yRB-nAWFrncJrRpei6lQKK9pWs7--j_boHCAB8Ud2fy3ypJibX04J7dGMn1LTCQdCtwjtjzya3BsAN8pfAswiL_k-X3U4jmXqOD_Exom2yh1J_zLA6E96QnPb3NmYaACbX5Y4PS4Qh-bj-TkABpD_hQcx2poHztD7EYIURY9KlE',
          q: 'xJBhxWQfBaesXc7UJSuNvGfxrBXGDReIiLro3XzzEMOkm5GjyEEkTuOVPN9KFZDuIG3KSGTz5Sm1LN4a7ShHXDle5CZ9Fc1q2E_Rs5-Mi-34DKNkUYcgXXo6h_zBrV1mDNZbPpjrQTZY1MVUIVn6FYq44eJatNywD1ZPqXlF83E',
          dp: 'm91BiMlvHBQDWEF80V9rWF7CmTalynD-XJ1ZYqyXu4iBIXPhAWd0xLT6oeEnIdtM-EI3HOqaMldwIizdB9_Uu-2mHxJAmS50NuJUWgaH4JS4XUtGRYYVbDXCrG8VCtDzkNXFKH4M6JWADkgtxzaVRr1ood4G4U8cFGklwVYwDEE',
          dq: 'lo1PlXR-HkKyzpbf_ihBwxCKFhgHPXfM54zhVuOg-DIhHdaK75KVUKcXYyxS_fmnqcbtrE1GUTuEvPzQ-txi68w1VeH05IIVV-Cq6T1G1NZLqsJqz9cDfxVjR0zcuwBSbXqxIFzXs3cAytbo_TKBTYaW3MwWVXjCkLy2_0MXxME',
          qi: 'xL6te8sy_Bgd_jlCDzfu-NJwcw3d2HiJON_SM8EaycK-1sXEqfZPmjE1dAHXl3QfdbbRIdt6fNb3TkbQYA1Z20bsGifIwmvLxtz5letzw3wAI_2vDZc-qJAWqhpKiatCk6cB2UfUMrViH5RnGzmhvxmouVnAKp895qgIVwOHYHI',
        },
      ],
    };
    test('should fail if query does not contain response param ', async () => {
      expect(ipd.unpackProxyResponse()).rejects.toThrow();
    });

    test('should return a valid response with issuer_url', async () => {
      const successResponse =
        'eyJ0eXAiOiJqd3QiLCJhbGciOiJQUzI1NiIsImtpZCI6ImJBdzdXVnJmX1A2bDhuNEJfY1RNY0tvRWtScFFfUmNqUHAwektmc2JCbzAifQ.eyJpc3MiOiJodHRwczovL2lkcGFydG5lci5jb20iLCJleHAiOjE2NjUxOTc4ODIsImlhdCI6MTY2NTE5NzgyMiwic3ViIjoiZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW1WdVl5STZJa0V5TlRaRFFrTXRTRk0xTVRJaUxDSmpkSGtpT2lKS1YxUWlMQ0pyYVdRaU9pSjFOalJXYzBsQ0xXTjRXRE5PU0dZeGJsbHVNVTkwUWxodFYxZFJabHBhY0RKQ1ZrNHhjbHBNTmxoVklpd2lhWE56SWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvNU1EQXhJaXdpWVhWa0lqb2liVmg2U2pCVVNrVmlWMUZpTWtFNGN6RjZObWR4SW4wLnBvbFJQRnlmR0stS1p5Wkxwc0M5dU1lQ0VRRkFIZzRPS09yNGw3d0hKN08wazg0Q0hrU1Uwa3ExUXkzbEdDQmlWTWtaR296S3owQTF2VTdhNk1XZXhJTWdwTjY2Sm5jMlRONDA3d0Y5MXJ5ZlUxM0ppVi02RVYwXzZzSWs5TWVZVmxWNzRQQ2lnR2pfRzVNelIwNmJkc3FsLVZxQVFLWGsySVg4TWw5bnRZYU8zbmpPeHFYVU5mNUpZVEJLQ0NhbU5aVmF1eTVMVU1YcXo3MXJ3d3BYQmVRZTBva2JKaVF6TDFGUllaR2lIM3lNNDR0R051NnNKZ2tHNmdEdUNNc0Jwalg3OC00M2FUVHpIUE1nbXhtZUhieEJrVE84SXFlVC1NVzdtUktsSUJFcmVyZ01RWk5Eb3N5TU4tSjUxeFVkQmJZY2o1Q0d4YW5HQVc4QmFlT0Q3US56UnpsV1E3Nl92OXNHelprajNzUG5BLk1LejFSaFRnbDFvb1ZvOE9IeEswX2I1VWx3a3RBSU4yQmxoVmp4dXp1ODljSDNMTDZjMnhYZXgzR2VicEVGdXlvYWhxZGJpSjdwY3oxRU02am1VVGp2M0VCNk5WY3hCczhIdW1sMkl3VGdIRDdRMnR6LWVySm5YYmFJazB5Nmd5WW05YWQ0N1RKemQxVHloWV9QX29JTW5TaVFsRGRpYTcwZWhLdURRdnA4Mm1wMDk4QzJTT0l6cjVpRmxfWC1VRjd0VmNYS3p4NUhxQ1d6VmY0NlluaWVad3F6WkRTSGp0V1Z1ZDBrLUkxQzFfU1RkZ3lGbHY1MzB1WF9CS3BYcEhVM1p3NEJqSGZjcUEzQ0tqVG5hOWNOVENYbDZ2Uk5senQ0YkxrcVJ6ODlTYWs5Ykk5ck14MTdWRWVzZ005N3VXaGN4cFRkcjM3X3psdTdKWnpQOXRocWlqODAzTFA3Nzg0S0ZuWTk5ODBHbGo5VktXdnlGQUVfY29hZTRIMU1ZblNLejVyRWtrNEl3cmxyUjJ0cFJXa1JPazJJb28zbUhNNWZIMWF2RlQteVhaTngyOGpLV1Bnb09LNHlhbEEzTmNkbHEwbm10SFdvbnhXTFl2YUs1Vk9Wak1XaGNzenpwN0N3VTNHd0hTakxpTU0yWThNakFId1g4dnBWZThPc3l5MExxbkFDTU5fdnVRdUZfWjFycHdxT2FZT1Y1b3I3N0wzSlI2QXB0S1dBcWEyUXNLSnJBUzZUVDBURm9fZXkxUU1hWHFqdHJRdnJ0TXFBZ29UZ0wxMUR2Q0NHcXdvWnZ1M3loMmxRVEJ0QnJuV0hDS3BJVmhhYjNlWUZzNEtUdzJYZGVrUjAyNC1LUllxc0t2XzVob1dNdndvU0FkSF9ra3JwNDNRd3cyVlF4cmdhYVRyLXRMdm4tOUZwTDlZa0lxVUJENFdyWkV0WUxaQkNOcVBaVjEyVWtuUk51WTlLZ0J2NExaOGhoYjV5MkxpVkV6ZjhmRk1lUFdzcDVuZWg4YS1GTVN3alB4MXhaWWhQTko1Nm1vWTBnenJIVVQ2ZnFSTGU5b3lKT3RWY044RU1DVG9HeG1sQnl1blJrbmw1ajB3eDZJVG1KZEtUbHpNUElGNzJZYjc0M2FXM1YySDJtdlJOZVV4N0pDZUx6QWRsbmxldkJIOWEybUVLUEZmUzVPZ0JfeEFaWWNpWEtzdjFVenc3UVlBXzVUdlAweWh1YXhTQlBpMXBxTXdpOC4yRHNoUndJUERYb3paSEk2SDhseUo1OHZmMnYxc3lLbS1WRFVhSjJuc0Y0IiwiYXVkIjoibVh6SjBUSkViV1FiMkE4czF6NmdxIiwieC1mYXBpLWludGVyYWN0aW9uLWlkIjoiZjhjM2YzNGEtNWUyNy00YzVlLWE5YTItNTIyMDQ1YTk4ZWEzIiwiaWRlbnRpdHlfcHJvdmlkZXIiOnsibmFtZSI6IkFrb3lhIE1pa29tbyBtb2NrIGJhbmsiLCJpc3N1ZXJfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAxIn19.b_x8Hxg8ZTUHOYcNCC7jq7_E8GJ49TeT8lWqK_8F6oThAYw6mE5SWiF4Q3yuW_ebdydH96QYkTz_73rrmwJVYGd6T_7WvYdy58788TJTkkDXjrfevat2zfj0tX4tiKPFEKRPx4ak_bGA_hl2BuVbJBBdWpLfV8k_l9B7DuyObdjYPNUiv3EdKahjfemAsaNCfELHQgO2ju0eAF3IHt1it_F0Ne8tdASQnXPS0vOBdJ141-M5PIcCILY6V6vixLPqVlBCWjTUeCWbuNUWoLpdKVOJCWaw6iZ_j9VkeU1fS8wCLMMEAvqH9r-8SwIrIZYTQqmkxuOwWf6kyBQ66-k5Ag';

      const result = await ipd.unpackProxyResponse({ response: successResponse });
      expect(result.identity_provider).toHaveProperty('issuer_url');
    });
    test('should return a valid response with jwt response code', async () => {
      const successResponse =
        'eyJ0eXAiOiJqd3QiLCJhbGciOiJQUzI1NiIsImtpZCI6ImJBdzdXVnJmX1A2bDhuNEJfY1RNY0tvRWtScFFfUmNqUHAwektmc2JCbzAifQ.eyJpc3MiOiJodHRwczovL2lkcGFydG5lci5jb20iLCJleHAiOjE2NjUxOTc4ODIsImlhdCI6MTY2NTE5NzgyMiwic3ViIjoiZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW1WdVl5STZJa0V5TlRaRFFrTXRTRk0xTVRJaUxDSmpkSGtpT2lKS1YxUWlMQ0pyYVdRaU9pSjFOalJXYzBsQ0xXTjRXRE5PU0dZeGJsbHVNVTkwUWxodFYxZFJabHBhY0RKQ1ZrNHhjbHBNTmxoVklpd2lhWE56SWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvNU1EQXhJaXdpWVhWa0lqb2liVmg2U2pCVVNrVmlWMUZpTWtFNGN6RjZObWR4SW4wLnBvbFJQRnlmR0stS1p5Wkxwc0M5dU1lQ0VRRkFIZzRPS09yNGw3d0hKN08wazg0Q0hrU1Uwa3ExUXkzbEdDQmlWTWtaR296S3owQTF2VTdhNk1XZXhJTWdwTjY2Sm5jMlRONDA3d0Y5MXJ5ZlUxM0ppVi02RVYwXzZzSWs5TWVZVmxWNzRQQ2lnR2pfRzVNelIwNmJkc3FsLVZxQVFLWGsySVg4TWw5bnRZYU8zbmpPeHFYVU5mNUpZVEJLQ0NhbU5aVmF1eTVMVU1YcXo3MXJ3d3BYQmVRZTBva2JKaVF6TDFGUllaR2lIM3lNNDR0R051NnNKZ2tHNmdEdUNNc0Jwalg3OC00M2FUVHpIUE1nbXhtZUhieEJrVE84SXFlVC1NVzdtUktsSUJFcmVyZ01RWk5Eb3N5TU4tSjUxeFVkQmJZY2o1Q0d4YW5HQVc4QmFlT0Q3US56UnpsV1E3Nl92OXNHelprajNzUG5BLk1LejFSaFRnbDFvb1ZvOE9IeEswX2I1VWx3a3RBSU4yQmxoVmp4dXp1ODljSDNMTDZjMnhYZXgzR2VicEVGdXlvYWhxZGJpSjdwY3oxRU02am1VVGp2M0VCNk5WY3hCczhIdW1sMkl3VGdIRDdRMnR6LWVySm5YYmFJazB5Nmd5WW05YWQ0N1RKemQxVHloWV9QX29JTW5TaVFsRGRpYTcwZWhLdURRdnA4Mm1wMDk4QzJTT0l6cjVpRmxfWC1VRjd0VmNYS3p4NUhxQ1d6VmY0NlluaWVad3F6WkRTSGp0V1Z1ZDBrLUkxQzFfU1RkZ3lGbHY1MzB1WF9CS3BYcEhVM1p3NEJqSGZjcUEzQ0tqVG5hOWNOVENYbDZ2Uk5senQ0YkxrcVJ6ODlTYWs5Ykk5ck14MTdWRWVzZ005N3VXaGN4cFRkcjM3X3psdTdKWnpQOXRocWlqODAzTFA3Nzg0S0ZuWTk5ODBHbGo5VktXdnlGQUVfY29hZTRIMU1ZblNLejVyRWtrNEl3cmxyUjJ0cFJXa1JPazJJb28zbUhNNWZIMWF2RlQteVhaTngyOGpLV1Bnb09LNHlhbEEzTmNkbHEwbm10SFdvbnhXTFl2YUs1Vk9Wak1XaGNzenpwN0N3VTNHd0hTakxpTU0yWThNakFId1g4dnBWZThPc3l5MExxbkFDTU5fdnVRdUZfWjFycHdxT2FZT1Y1b3I3N0wzSlI2QXB0S1dBcWEyUXNLSnJBUzZUVDBURm9fZXkxUU1hWHFqdHJRdnJ0TXFBZ29UZ0wxMUR2Q0NHcXdvWnZ1M3loMmxRVEJ0QnJuV0hDS3BJVmhhYjNlWUZzNEtUdzJYZGVrUjAyNC1LUllxc0t2XzVob1dNdndvU0FkSF9ra3JwNDNRd3cyVlF4cmdhYVRyLXRMdm4tOUZwTDlZa0lxVUJENFdyWkV0WUxaQkNOcVBaVjEyVWtuUk51WTlLZ0J2NExaOGhoYjV5MkxpVkV6ZjhmRk1lUFdzcDVuZWg4YS1GTVN3alB4MXhaWWhQTko1Nm1vWTBnenJIVVQ2ZnFSTGU5b3lKT3RWY044RU1DVG9HeG1sQnl1blJrbmw1ajB3eDZJVG1KZEtUbHpNUElGNzJZYjc0M2FXM1YySDJtdlJOZVV4N0pDZUx6QWRsbmxldkJIOWEybUVLUEZmUzVPZ0JfeEFaWWNpWEtzdjFVenc3UVlBXzVUdlAweWh1YXhTQlBpMXBxTXdpOC4yRHNoUndJUERYb3paSEk2SDhseUo1OHZmMnYxc3lLbS1WRFVhSjJuc0Y0IiwiYXVkIjoibVh6SjBUSkViV1FiMkE4czF6NmdxIiwieC1mYXBpLWludGVyYWN0aW9uLWlkIjoiZjhjM2YzNGEtNWUyNy00YzVlLWE5YTItNTIyMDQ1YTk4ZWEzIiwiaWRlbnRpdHlfcHJvdmlkZXIiOnsibmFtZSI6IkFrb3lhIE1pa29tbyBtb2NrIGJhbmsiLCJpc3N1ZXJfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAxIn19.b_x8Hxg8ZTUHOYcNCC7jq7_E8GJ49TeT8lWqK_8F6oThAYw6mE5SWiF4Q3yuW_ebdydH96QYkTz_73rrmwJVYGd6T_7WvYdy58788TJTkkDXjrfevat2zfj0tX4tiKPFEKRPx4ak_bGA_hl2BuVbJBBdWpLfV8k_l9B7DuyObdjYPNUiv3EdKahjfemAsaNCfELHQgO2ju0eAF3IHt1it_F0Ne8tdASQnXPS0vOBdJ141-M5PIcCILY6V6vixLPqVlBCWjTUeCWbuNUWoLpdKVOJCWaw6iZ_j9VkeU1fS8wCLMMEAvqH9r-8SwIrIZYTQqmkxuOwWf6kyBQ66-k5Ag';

      const result = await ipd.unpackProxyResponse({ response: successResponse });
      expect(result).toHaveProperty('idp_response_code');
    });
    test('should fail if a non IDPartner JWT is returned', async () => {
      const successResponse =
        'eyJ0eXAiOiJqd3QiLCJhbGciOiJQUzI1NiIsImtpZCI6ImJBdzdXVnJmX1A2bDhuNEJfY1RNY0tvRWtScFFfUmNqUHAwektmc2JCbzAifQ.eyJpc3MiOiJodHRwczovL2lkcGFydG5lci5jb20iLCJleHAiOjE2NjUxOTc4ODIsImlhdCI6MTY2NTE5NzgyMiwic3ViIjoiZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW1WdVl5STZJa0V5TlRaRFFrTXRTRk0xTVRJaUxDSmpkSGtpT2lKS1YxUWlMQ0pyYVdRaU9pSjFOalJXYzBsQ0xXTjRXRE5PU0dZeGJsbHVNVTkwUWxodFYxZFJabHBhY0RKQ1ZrNHhjbHBNTmxoVklpd2lhWE56SWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvNU1EQXhJaXdpWVhWa0lqb2liVmg2U2pCVVNrVmlWMUZpTWtFNGN6RjZObWR4SW4wLnBvbFJQRnlmR0stS1p5Wkxwc0M5dU1lQ0VRRkFIZzRPS09yNGw3d0hKN08wazg0Q0hrU1Uwa3ExUXkzbEdDQmlWTWtaR296S3owQTF2VTdhNk1XZXhJTWdwTjY2Sm5jMlRONDA3d0Y5MXJ5ZlUxM0ppVi02RVYwXzZzSWs5TWVZVmxWNzRQQ2lnR2pfRzVNelIwNmJkc3FsLVZxQVFLWGsySVg4TWw5bnRZYU8zbmpPeHFYVU5mNUpZVEJLQ0NhbU5aVmF1eTVMVU1YcXo3MXJ3d3BYQmVRZTBva2JKaVF6TDFGUllaR2lIM3lNNDR0R051NnNKZ2tHNmdEdUNNc0Jwalg3OC00M2FUVHpIUE1nbXhtZUhieEJrVE84SXFlVC1NVzdtUktsSUJFcmVyZ01RWk5Eb3N5TU4tSjUxeFVkQmJZY2o1Q0d4YW5HQVc4QmFlT0Q3US56UnpsV1E3Nl92OXNHelprajNzUG5BLk1LejFSaFRnbDFvb1ZvOE9IeEswX2I1VWx3a3RBSU4yQmxoVmp4dXp1ODljSDNMTDZjMnhYZXgzR2VicEVGdXlvYWhxZGJpSjdwY3oxRU02am1VVGp2M0VCNk5WY3hCczhIdW1sMkl3VGdIRDdRMnR6LWVySm5YYmFJazB5Nmd5WW05YWQ0N1RKemQxVHloWV9QX29JTW5TaVFsRGRpYTcwZWhLdURRdnA4Mm1wMDk4QzJTT0l6cjVpRmxfWC1VRjd0VmNYS3p4NUhxQ1d6VmY0NlluaWVad3F6WkRTSGp0V1Z1ZDBrLUkxQzFfU1RkZ3lGbHY1MzB1WF9CS3BYcEhVM1p3NEJqSGZjcUEzQ0tqVG5hOWNOVENYbDZ2Uk5senQ0YkxrcVJ6ODlTYWs5Ykk5ck14MTdWRWVzZ005N3VXaGN4cFRkcjM3X3psdTdKWnpQOXRocWlqODAzTFA3Nzg0S0ZuWTk5ODBHbGo5VktXdnlGQUVfY29hZTRIMU1ZblNLejVyRWtrNEl3cmxyUjJ0cFJXa1JPazJJb28zbUhNNWZIMWF2RlQteVhaTngyOGpLV1Bnb09LNHlhbEEzTmNkbHEwbm10SFdvbnhXTFl2YUs1Vk9Wak1XaGNzenpwN0N3VTNHd0hTakxpTU0yWThNakFId1g4dnBWZThPc3l5MExxbkFDTU5fdnVRdUZfWjFycHdxT2FZT1Y1b3I3N0wzSlI2QXB0S1dBcWEyUXNLSnJBUzZUVDBURm9fZXkxUU1hWHFqdHJRdnJ0TXFBZ29UZ0wxMUR2Q0NHcXdvWnZ1M3loMmxRVEJ0QnJuV0hDS3BJVmhhYjNlWUZzNEtUdzJYZGVrUjAyNC1LUllxc0t2XzVob1dNdndvU0FkSF9ra3JwNDNRd3cyVlF4cmdhYVRyLXRMdm4tOUZwTDlZa0lxVUJENFdyWkV0WUxaQkNOcVBaVjEyVWtuUk51WTlLZ0J2NExaOGhoYjV5MkxpVkV6ZjhmRk1lUFdzcDVuZWg4YS1GTVN3alB4MXhaWWhQTko1Nm1vWTBnenJIVVQ2ZnFSTGU5b3lKT3RWY044RU1DVG9HeG1sQnl1blJrbmw1ajB3eDZJVG1KZEtUbHpNUElGNzJZYjc0M2FXM1YySDJtdlJOZVV4N0pDZUx6QWRsbmxldkJIOWEybUVLUEZmUzVPZ0JfeEFaWWNpWEtzdjFVenc3UVlBXzVUdlAweWh1YXhTQlBpMXBxTXdpOC4yRHNoUndJUERYb3paSEk2SDhseUo1OHZmMnYxc3lLbS1WRFVhSjJuc0Y0IiwiYXVkIjoibVh6SjBUSkViV1FiMkE4czF6NmdxIiwieC1mYXBpLWludGVyYWN0aW9uLWlkIjoiZjhjM2YzNGEtNWUyNy00YzVlLWE5YTItNTIyMDQ1YTk4ZWEzIiwiaWRlbnRpdHlfcHJvdmlkZXIiOnsibmFtZSI6IkFrb3lhIE1pa29tbyBtb2NrIGJhbmsiLCJpc3N1ZXJfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAxIn19.b_x8Hxg8ZTUHOYcNCC7jq7_E8GJ49TeT8lWqK_8F6oThAYw6mE5SWiF4Q3yuW_ebdydH96QYkTz_73rrmwJVYGd6T_7WvYdy58788TJTkkDXjrfevat2zfj0tX4tiKPFEKRPx4ak_bGA_hl2BuVbJBBdWpLfV8k_l9B7DuyObdjYPNUiv3EdKahjfemAsaNCfELHQgO2ju0eAF3IHt1it_F0Ne8tdASQnXPS0vOBdJ141-M5PIcCILY6V6vixLPqVlBCWjTUeCWbuNUWoLpdKVOJCWaw6iZ_j9VkeU1fS8wCLMMEAvqH9r-8SwIrIZYTQqmkxuOwWf6kyBQ66-WRONG';

      expect(ipd.unpackProxyResponse({ response: successResponse })).rejects.toThrow();
    });
  });
});
