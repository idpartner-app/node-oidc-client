# Example using private_key_jwt auth method

The usage of `private_key_jwt` is deprecated and we will stop supporting it soon. If you are already using it please migrate to `tls_client_auth`. If you are implemeting a brand new integration please use `tls_client_auth`.

<br>

## Client initialization

```javascript
const IDPartner = require('@idpartner/node-oidc-client');

const rawJWKS = fs.readFileSync('jwks.json');
const jwks = JSON.parse(rawJWKS);
const idPartner = new IDPartner({
  jwks, // Private/public keys used to verify and decrypt any JSON Web Token (JWT) issued by the identity provider authorization server
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq', // Your application's client ID
  callback: 'https://myapplication.com/auth/callback', // The location you want the app to return to on success
  token_endpoint_auth_method: 'private_key_jwt', // The auth method to use
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
  token_endpoint_auth_method: 'private_key_jwt',
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
  token_endpoint_auth_method: 'private_key_jwt',
});

router.get('/jwks', (req, res, next) => {
  const jwks = await idPartner.getPublicJWKs();
  res.send(jwks);
});

router.get('/auth', (req, res, next) => {
  // Specify prompt=consent and scope=offline_access to get a refresh token that can be used to fetch full user info later on.
  const prompt = 'consent';
  const scope = ['openid', 'email', 'profile', 'offline_access'];
  const extraAuthorizationParams = { prompt }
  req.session.idp_proofs = idPartner.generateProofs()
  req.session.issuer = req.query.iss;
  const authorizationUrl = await idPartner.getAuthorizationUrl(req.query, req.session.idp_proofs, scope, extraAuthorizationParams);
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