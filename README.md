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
  jwks,
  client_id: '128ecf542a35ac5270a87dc740918404',
  callback: 'https://myapplication.com/auth/callback',
});
```

#### To generate a JWKS you can use [mkjwk.org](mkjwk.org) service to generate a key pair for signing and encryption or use [node-jose](https://github.com/cisco/node-jose) library


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

## Authorization

Set up your IDPartner as above and pass the following configuration options in:

```
{
  client_id: 'Your application's client ID',
  callback: 'The location you want the app to return to on success',
  jwks: 'Private/public keys used to verify and decrypt any JSON Web Token (JWT) issued by the identity provider authorization server
}
```

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
| `scope` | `array` | **Required**. Specify the user attributes your require for your application [IDPartner supports the standard OIDC scopes](https://openid.net/specs/openid-connect-basic-1_0.html#Scopes). For example - `["openid", "email", "address"]`

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

## Testing

```
yarn test
```
