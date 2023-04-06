# IDPartner for Node.js

A node module for authentication and use with the IDPartner Trust API

## Installation

To install the module using NPM:

```
npm install @idpartner/node-oidc-client
```

Or Yarn:

```
yarn add @idpartner/node-oidc-client
```

## Setup

Include the `@idpartner/node-oidc-client` module within your script and instantiate it with a config:

```javascript
const IDPartner = require('@idpartner/node-oidc-client');

const rawJWKS = fs.readFileSync('jwks.json');
const jwks = JSON.parse(rawJWKS);
const idPartner = new IDPartner({
  jwks, // Private/public keys used to verify and decrypt any JSON Web Token (JWT) issued by the identity provider authorization server
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq', // Your application's client ID
  callback: 'https://myapplication.com/auth/callback' // The location you want the app to return to on success
});
```

**To generate a JWKS you can use [mkjwk.org](mkjwk.org) service to generate a key pair for signing and encryption or use [node-jose](https://github.com/cisco/node-jose) library**


For example:

```javascript
const jose = require('node-jose');

const keyStore = jose.JWK.createKeyStore();
keyStore.generate('RSA', 2048, { alg: 'RSA-OAEP', enc: 'A256CBC-HS512', use: 'enc' }));
keyStore.generate('RSA', 2048, { alg: 'PS256', use: 'sig' }));
const JWKS = keyStore.toJSON(true);
```

> Instantiating a IDPartner instance without a config object will result in an error

<br>

## Authorization with Synchronous Full User Info

```javascript
const express = require('express'),
  router = express.Router(),
  IDPartner = require('@idpartner/node-oidc-client');

const rawJWKS = fs.readFileSync('jwks.json');
const jwks = JSON.parse(rawJWKS);

const idPartner = new IDPartner({
  jwks,
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq',
  callback: 'https://myapplication.com/auth/callback',
});

router.get('/jwks', (req, res, next) => {
  const jwks = await idPartner.getPublicJWKs();
  res.send(jwks);
});

router.get('/auth', (req, res, next) => {
  const scope = ['openid', 'email', 'profile'];
  req.session.idp_proofs = idPartner.generateProofs()
  req.session.issuer = req.query.iss;
  const authorizationUrl = await idPartner.getAuthorizationUrl(req.query, req.session.idp_proofs, scope);
  res.redirect(authorizationUrl);
});

router.get('/auth/callback', (req, res, next) => {
  const claims = await idPartner.claims(req.query.response, req.session.issuer, req.session.idp_proofs);
  return res.send(claims);
  }
});
```

<br>

## Authorization with Synchronous Basic User Info and Asynchronous Full User Info

```javascript
const express = require('express'),
  router = express.Router(),
  IDPartner = require('@idpartner/node-oidc-client');

const rawJWKS = fs.readFileSync('jwks.json');
const jwks = JSON.parse(rawJWKS);

const idPartner = new IDPartner({
  jwks,
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq',
  callback: 'https://myapplication.com/auth/callback',
});

router.get('/jwks', (req, res, next) => {
  const jwks = await idPartner.getPublicJWKs();
  res.send(jwks);
});

router.get('/auth', (req, res, next) => {
  // Specify consent=prompt and scope=offline_access to get a refresh token that can be used to fetch full user info later on.
  const prompt = 'consent';
  const scope = ['openid', 'email', 'profile', 'offline_access'];
  req.session.idp_proofs = idPartner.generateProofs()
  req.session.issuer = req.query.iss;
  const authorizationUrl = await idPartner.getAuthorizationUrl(req.query, req.session.idp_proofs, scope, prompt);
  res.redirect(authorizationUrl);
});

router.get('/auth/callback', (req, res, next) => {
  const token = await idPartner.token(req.query.response, req.session.issuer, req.session.idp_proofs);
  const claims = await idPartner.basicUserInfo(req.session.issuer, token)
  // Refresh token should be encrypted and stored in a secure place. Storing it in session just for demonstration purposes.
  req.session.refresh_token = token.refresh_token;
  return res.send(claims);
});

router.get('/auth/userinfo', (req, res, next) => {
  const token = await idPartner.refreshToken(req.session.issuer, req.session.refresh_token);
  const claims = await idPartner.userInfo(req.session.issuer, token)
  return res.send(claims);
});
```

### generateProofs

A helper method to generate a `state`, `nonce` and `codeVerifier` which is used for validating the Identity response and protecting against cross site request forgery(CSRF) attacks

```javascript
 {
  state: 'b6P4_eFMVTx_CFznmaHj9geXQUVm_z-xa8QgEmHEdNE',
  nonce: 'PVShAu4ZMyfPd6zV-GitTmu-yi3TFxPJhCjv8wjyweY',
  codeVerifier: 'Ek8FS-7c3AqTA-rPzF9c8-acO_-Mg4J3hpiKEzKllpc'
}
```

<br>

### getAuthorizationUrl

Creates an authorization url with a signed JWT (using the private key in the JKWS). Since IDPartner implements the authorization code flow you should redirect to this URL.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `query` | `string` | **Required**. The query parameters that started the authorization flow after the end user clicks the IDPartner Button
| `proofs` | `string` | **Required**. Use helper method `generateProofs` to generate a `state`, `nonce` and `codeVerifier` used for security & validations purposes
| `scope` | `array` | **Required**. Specify the user attributes your require for your application [IDPartner supports the standard OIDC scopes](https://openid.net/specs/openid-connect-basic-1_0.html#Scopes). For example - `["openid", "email", "address", "offline_access"]`
| `prompt` | `string` | **Optional**. Specify it as `prompt` if you need an access token returned by the OP

<br>

Example response

```http
https://auth-api.idpartner.com/oidc-proxy/auth?request=eyJhbGciOiJQUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiIzZUxfTFNFZ0VIQ05hNDVtd1U3elo4M1NFSHZYMk1lc2RLV2NQMTRqUThzIn0.eyJyZWRpcmVjdF91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEvYnV0dG9uL29hdXRoL2NhbGxiYWNrIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsImNvZGVfY2hhbGxlbmdlIjoiRWRkMDBfUnB3RjZnbVh2TS1KY1V0ZUwzeVRCeFRHV0l3ejFKX1J2WUZROCIsInN0YXRlIjoiSWhnc1BqT3FOVGtHMmM3SWhPZGdNdGhFNEFtOFllUS1jcnRkUkpqRFBkOCIsIm5vbmNlIjoiS1ZKa1pFWFYxWTdaN25XNkN6QmY1eEVHMzA4MFY2V3dVZFNqc1NUbVJUdyIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJyZXNwb25zZV9tb2RlIjoiand0IiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJjbGllbnRfaWQiOiJtWHpKMFRKRWJXUWIyQThzMXo2Z3EiLCJuYmYiOjE2NjU1MzQzMTgsIngtZmFwaS1pbnRlcmFjdGlvbi1pZCI6ImVjNTY1M2ZkLWNmZTQtNDdkZC1hNGIxLTEwNDhlN2M3NGVhNyIsImlzcyI6Im1YekowVEpFYldRYjJBOHMxejZncSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMSIsImp0aSI6ImJyRlpDVndka2FLOHVERDVtTmJNMEh3a3Y1WEUwUmpxN1BqdklVV2JranMiLCJpYXQiOjE2NjU1MzQzMTgsImV4cCI6MTY2NTUzNDYxOH0.YUeUNDqneO1tss09chSABZ2zrQjQK0DjFJQ3osw8VwnAISYRaViZUGwJXbLGp-dpYntppmBU55JH4rs5Zbt7I2UAnaQPy_HEpfsQ-cZ-kJH9XVErtCqfck35hO5EdgWkprXFDPluN6JSyEFv2dud2vEXqJbf8iwhDInmAdEwtb_pcwrEWG_F-vFzRUjWWPip4MikShX2NortqgDsZhf50nXBFoKHz5FGHv_VULNSeOV-T1FJ7LNP2oXLfe6YO8xg-7waBR_9dF8pspAd0veykLo-4Z-cWVm8rAcirc2uLGJtgQ_tMRQV9fQWT88mehC1hFIV7VFUfgttyY68zfkGuQ&visitor_id=123NBwiSKIDqyDKdgabc

```

<br>

### claims

Returns the consented identity details

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `response` | `string` | **Required**. The signed and encrypted JWT response code returned from the issuer
| `issuer` | `string` | **Required**. The issuer url. It must be the same than the one used to get the authorization url
| `proofs` | `object` | **Required**. The proofs that were generated during the `getAuthorizationUrl` phase

An example data object:

```javascript
{
  email: "john@idpartner.com",
  family_name: "John",
  given_name: "Doe",
  address: {
    street_address: '7572 CHOWNING RD',
    locality: 'SPRINGFIELD',
    region: 'TN',
    postal_code: '37172-6488'
  }
}
```

<br>

### token

Returns the access token requested to the OP

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `response` | `string` | **Required**. The signed and encrypted JWT response code returned from the issuer
| `issuer` | `string` | **Required**. The issuer url. It must be the same than the one used to get the authorization url
| `proofs` | `object` | **Required**. The proofs that were generated during the `getAuthorizationUrl` phase

An example data object:

```javascript
{
  access_token: 'Bw46G9pHPg3IRW5bAPDSRFPzD88jghkAcl4g2wSc0X-',
  refresh_token: 'HsdPir0TEi4TiiyUXa90sQGauOqUkmyJ4SDUGU8xL4cKlaf4BbHMO0c4uebs-',
  expires_at: 1680738657,
  id_token: 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii1NXzl2cUppMHRTWURlWEZoM2Nsdlo3MG50Qm9zVVZUOWFxQi0tMlNRaVUifQ.eyJzdWIiOiJkMDQ5YTYxOC05OGU1LTQ5MjItYjkxOS1kNTU3MjEwOGE5NTIiLCJlbWFpbCI6IlBoaWxpcEhMb3ZldHRAbWlrb21vdGVzdC5jb20iLCJmYW1pbHlfbmFtZSI6IkxvdmV0dCIsImdpdmVuX25hbWUiOiJQaGlsaXAiLCJub25jZSI6IkRzc185UXdlLTk5bGU1NGlsaUtKUHhreTdkQm1TLVUtR3FQMEd6WDUxUVUiLCJhdF9oYXNoIjoiZ21rdGpTa0xIaUl4eWo2VHpPa2pTQSIsImF1ZCI6IjV0THJ4dEZTRTRqQXRQWXRkeUNRWSIsImV4cCI6MTY4MDczODY1NywiaWF0IjoxNjgwNzM4NTk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEifQ.HxtbBftvGhGutmS1pC-PGpYJU7eONOuRjumIwlkD3A5Y6yzyjdZWKgj7JoA8qIO2NPDtoYwFVDV5E4gAADiun3SMBQ2mE0_ho9mfGbuskv9BC6VWSt_Z6eJHrWq83fpJrRxJGS16nSdCFo-0f8l71fl2BZdTlINxkTadu5Sc01e0usXkAlQIhtAwvCzcg-4RA5VePVaEhG_8OGxG8hPcyEMYvYpKlQ3XcaVTBRADmB0ody58RpKrEiR1AJyeha99v2HI-oGC62DpyK04SsTEcEzied9BDlEpsygWyQSqWa2gRW5Oov2FXAy37zcdYqGLG0nILZbSIX3lVJttD839wA',
  scope: 'openid email profile address offline_access',
  token_type: 'Bearer'
}
```

<br>

### refreshToken

Receives a refresh token and returns a new access token

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `issuer` | `string` | **Required**. The issuer url. It must be the same than the one used to get the authorization url
| `refreshToken` | `string` | **Required**. The refresh token returned as part of the token returned when the call to `token` function was made

An example data object:

```javascript
{
  access_token: 'Bw46G9pHPg3IRW5bAPDSRFPzD88jghkAcl4g2wSc0X-',
  refresh_token: 'HsdPir0TEi4TiiyUXa90sQGauOqUkmyJ4SDUGU8xL4cKlaf4BbHMO0c4uebs-',
  expires_at: 1680738657,
  id_token: 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii1NXzl2cUppMHRTWURlWEZoM2Nsdlo3MG50Qm9zVVZUOWFxQi0tMlNRaVUifQ.eyJzdWIiOiJkMDQ5YTYxOC05OGU1LTQ5MjItYjkxOS1kNTU3MjEwOGE5NTIiLCJlbWFpbCI6IlBoaWxpcEhMb3ZldHRAbWlrb21vdGVzdC5jb20iLCJmYW1pbHlfbmFtZSI6IkxvdmV0dCIsImdpdmVuX25hbWUiOiJQaGlsaXAiLCJub25jZSI6IkRzc185UXdlLTk5bGU1NGlsaUtKUHhreTdkQm1TLVUtR3FQMEd6WDUxUVUiLCJhdF9oYXNoIjoiZ21rdGpTa0xIaUl4eWo2VHpPa2pTQSIsImF1ZCI6IjV0THJ4dEZTRTRqQXRQWXRkeUNRWSIsImV4cCI6MTY4MDczODY1NywiaWF0IjoxNjgwNzM4NTk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEifQ.HxtbBftvGhGutmS1pC-PGpYJU7eONOuRjumIwlkD3A5Y6yzyjdZWKgj7JoA8qIO2NPDtoYwFVDV5E4gAADiun3SMBQ2mE0_ho9mfGbuskv9BC6VWSt_Z6eJHrWq83fpJrRxJGS16nSdCFo-0f8l71fl2BZdTlINxkTadu5Sc01e0usXkAlQIhtAwvCzcg-4RA5VePVaEhG_8OGxG8hPcyEMYvYpKlQ3XcaVTBRADmB0ody58RpKrEiR1AJyeha99v2HI-oGC62DpyK04SsTEcEzied9BDlEpsygWyQSqWa2gRW5Oov2FXAy37zcdYqGLG0nILZbSIX3lVJttD839wA',
  scope: 'openid email profile address offline_access',
  token_type: 'Bearer'
}
```

<br>

### basicUserInfo

Returns the proof of humanity from the consented identity details. It's composed by email, given name and family name assuming that they all were requested within the scope of the initial authorization request

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `issuer` | `string` | **Required**. The issuer url. It must be the same than the one used to get the authorization url
| `token` | `object` | **Required**. The token object returned by the `token` or `refreshToken` function

An example data object:

```javascript
{
  sub: "2b6a41ea-9c23-4cd2-8795-db1010f1899e",
  email: "john@idpartner.com",
  family_name: "John",
  given_name: "Doe",
  aud: "mXzJ0TJEbWQb2A8s1z6gq",
  exp: 1664947625,
  iat: 1664944025,
  iss: "http://identity.chase.com"
}
```

<br>

### userInfo

Returns the consented identity details

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `issuer` | `string` | **Required**. The issuer url. It must be the same than the one used to get the authorization url
| `token` | `object` | **Required**. The token object returned by the `token` or `refreshToken` function

An example data object:

```javascript
{
  email: "john@idpartner.com",
  family_name: "John",
  given_name: "Doe",
  address: {
    street_address: '7572 CHOWNING RD',
    locality: 'SPRINGFIELD',
    region: 'TN',
    postal_code: '37172-6488'
  }
}
```

## Testing

```
yarn test
```
