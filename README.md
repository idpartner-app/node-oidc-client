# IDPartner for Node.js

A node module for authentication and use with the IDPartner Trust API

## Installation

To install the module using NPM:

```
npm install node-oidc-client
```

Or Yarn:

```
yarn add node-oidc-client
```

## Setup

Include the 'node-oidc-client' module within your script and instantiate it with a config:

```javascript
const IDPartner = require('node-oidc-client');

const rawJWKS = fs.readFileSync('jwks.json');
const jwks = JSON.parse(rawJWKS);
const idPartner = new IDPartner({
  jwks,
  client_id: '128ecf542a35ac5270a87dc740918404',
  callback: 'https://myapplication.com/auth/callback',
});
```

### To generate a JWKS you can use (mkjwk.org)[mkjwk.org] service to generate a key pair for signing and encryption or use [node-jose](https://github.com/cisco/node-jose) library

For example:

```javascript
const jose = require('node-jose');

const keyStore = jose.JWK.createKeyStore();
keyStore.generate('RSA', 2048, { alg: 'RSA-OAEP', enc: 'A256CBC-HS512', use: 'enc' }));
keyStore.generate('RSA', 2048, { alg: 'PS256', use: 'sig' }));
const JWKS = keyStore.toJSON(true);
```

##### Instantiating a IDPartner instance without a config object will result in an error


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
  IDPartner = require('node-oidc-client');

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
  const authorizationUrl = await idPartner.getAuthorizationUrl(req.query, req.session.idp_proofs, scope);
  res.redirect(authorizationUrl);
});

router.get('/auth/callback', (req, res, next) => {
  const { idp_response_code } = await idPartner.unpackProxyResponse(req.query);
  const claims = await idPartner.claims(idp_response_code, req.session.idp_proofs);
  return res.send(claims);
  }
});
```

`generateProofs`

A helper method to generate a `state`, `nonce` and `codeVerifier` which is used for validating the Identity response and protecting against cross site request forgery(CSRF) attacks

```javascript
 {
  state: 'b6P4_eFMVTx_CFznmaHj9geXQUVm_z-xa8QgEmHEdNE',
  nonce: 'PVShAu4ZMyfPd6zV-GitTmu-yi3TFxPJhCjv8wjyweY',
  codeVerifier: 'Ek8FS-7c3AqTA-rPzF9c8-acO_-Mg4J3hpiKEzKllpc'
}
```

The `getAuthorizationUrl` creates an authorization url with a signed JWT (using the private key in the JKWS). Since IDPartner implements the authorization code flow you should redirect to this URL.


| Parameter | Type | Description |
| :--- | :--- | :--- |
| `query` | `string` | **Required**. The query parameters that started the authorization flow after the end user clicks the IDPartner Button
| `proofs` | `string` | **Required**. Use helper method `generateProofs` to generate a `state`, `nonce` and `codeVerifier` used for security & validations purposes
| `scope` | `array` | **Required**. Specify the user attributes your require for your application [IDPartner supports the standard OIDC scopes](https://openid.net/specs/openid-connect-basic-1_0.html#Scopes). For example - `["openid", "email", "address"]`


Example response
```http
https://auth-api.idpartner.com/auth?request=ey...

```

The `verifyIdentityProviderDetails` method returns the identity provider the user selected from the selector. The object contains information about the provider and Know Your Business credentials that you can perform additional verification before request the consented claims.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `query` | `string` | **Required**. The query parameters of the callback url. The query parameters contain a signed JWT by IDPartner containing the issuer url as well as the identity provider details such as name.


Example response:

```javascript
{ 
 name: "Chase bank",
 issuer_url: "http://identity.chase.com"
}
```

```
The `claims` method returns the consented identity details

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `proofs` | `objects` | **Required**. The proofs that were generated during the `getAuthorizationUrl` phase

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
