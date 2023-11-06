# Example using tls_client_auth auth method without JWKs

The usage of `tls_client_auth` is required for production apps. 

If you need to implement JWKs (which are optional for our integration) see [Example using tls_client_auth with JWKS](./example_tls_client_auth_with_jwks.md).

<br>

## Client initialization

```javascript
const IDPartner = require('@idpartner/node-oidc-client');

const idPartner = new IDPartner({
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq', // Your application's client ID
  callback: 'https://myapplication.com/auth/callback', // The location you want the app to return to on success
  token_endpoint_auth_method: 'tls_client_auth', // The auth method to use
  tls_client_cert: fs.readFileSync('tls-client-cert.pem'), // The cert issued by IDPartner
  tls_client_key: fs.readFileSync('tls-client-key.key'), // They private key owned by you
});
```

**To have IDPartner to issue a certificate contact us at help@idpartner.com**

> Instantiating a IDPartner instance without a config object will result in an error

<br>

## Authorization with Synchronous Full User Info

```javascript
const express = require('express'),
  router = express.Router(),
  IDPartner = require('@idpartner/node-oidc-client');

const idPartner = new IDPartner({
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq',
  callback: 'https://myapplication.com/auth/callback',
  token_endpoint_auth_method: 'tls_client_auth',
  tls_client_cert: fs.readFileSync('tls-client-cert.pem'),
  tls_client_key: fs.readFileSync('tls-client-key.key'), 
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

const idPartner = new IDPartner({
  client_id: 'mXzJ0TJEbWQb2A8s1z6gq',
  callback: 'https://myapplication.com/auth/callback',
  token_endpoint_auth_method: 'tls_client_auth',
  tls_client_cert: fs.readFileSync('tls-client-cert.pem'),
  tls_client_key: fs.readFileSync('tls-client-key.key'), 
});

router.get('/auth', (req, res, next) => {
  // Specify prompt=consent and scope=offline_access to get a refresh token that can be used to fetch full user info later on.
  const prompt = 'consent';
  const scope = ['openid', 'email', 'profile', 'offline_access'];
  const extraAuthorizationParams = { prompt };
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