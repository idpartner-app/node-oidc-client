import { generators, Issuer } from 'openid-client';
import { v4 as uuidv4 } from 'uuid';
import { Application } from '../../models/application';
import { getJWKs } from '../../utils/rp-example-jwks';
import { verifyDocument } from './trust-management/document-verifier';

const SIGNING_ALG = 'PS256';
const ENCRYPTION_ALG = 'RSA-OAEP';
const ENCRYPTION_ENC = 'A256CBC-HS512';

const createClient = async (application, issuer) => {
  const jwks = await getJWKs({ includePrivateKeys: true });

  return new issuer.Client(
    {
      client_id: application.client_id,
      token_endpoint_auth_method: 'private_key_jwt',
      redirect_uris: application.redirect_url.split(','),
      authorization_signed_response_alg: SIGNING_ALG,
      authorization_encrypted_response_alg: ENCRYPTION_ALG,
      authorization_encrypted_response_enc: ENCRYPTION_ENC,
      id_token_signed_response_alg: SIGNING_ALG,
      id_token_encrypted_response_alg: ENCRYPTION_ALG,
      id_token_encrypted_response_enc: ENCRYPTION_ENC,
      userinfo_signed_response_alg: SIGNING_ALG,
      userinfo_encrypted_response_alg: ENCRYPTION_ALG,
      userinfo_encrypted_response_enc: ENCRYPTION_ENC,
      request_object_signing_alg: SIGNING_ALG,
    },
    jwks,
  );
};

exports.oauth = async (ctx, next) => {
  const { visitor_id, application_client_id } = ctx.query;
  const application = await Application.query().findOne({ client_id: application_client_id });
  if (!application) {
    ctx.status = 500;
    ctx.body = 'Application does not exist for client id';
    return;
  }

  const nonce = uuidv4();
  const transactionId = uuidv4();
  const scope = ['openid', 'email', 'profile'].join(' ');
  const state = generators.state();
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  const client = await createClient(application, ctx.issuer);

  ctx.session.clientId = application_client_id;
  ctx.session.state = state;
  ctx.session.nonce = nonce;
  ctx.session.codeVerifier = codeVerifier;

  const jwt = await client.requestObject({
    redirect_uri: application.redirect_url.split(',')[0],
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
    state,
    nonce,
    scope,
    response_mode: 'jwt',
    response_type: 'code',
    client_id: application_client_id,
    nbf: Math.floor(new Date().getTime() / 1000),
    'x-fapi-interaction-id': transactionId,
  });
  const authorizationUrl = `${process.env.BROKER_SERVICE_URL}/auth?request=${jwt}&visitor_id=${visitor_id}`;

  console.log(`Redirecting to ${authorizationUrl}`);
  ctx.redirect(authorizationUrl);
};

exports.oauthCallback = async (ctx, next) => {
  const application = await Application.query().findOne({ client_id: ctx.session.clientId });

  // Verify document is signed by IDPartner and get the nested response signed and encrypted by the OIDC Provider
  const { sub: nestedResponse } = await verifyDocument(ctx.query.response, ctx.session);

  // Create client using nested document issuer url
  const base64Header = nestedResponse.split('.')[0];
  const header = JSON.parse(Buffer.from(base64Header, 'base64'));
  const issuer = await Issuer.discover(header.iss);
  const client = await createClient(application, issuer);

  // Get access token and user info
  const params = { response: nestedResponse };
  const tokenSet = await client.callback(client.redirect_uris[0], params, { jarm: true, state: ctx.session.state, nonce: ctx.session.nonce, code_verifier: ctx.session.codeVerifier });
  // console.log('received and validated tokens', tokenSet);
  // console.log('validated ID Token claims', tokenSet.claims());
  const info = await client.userinfo(tokenSet);

  // Return user info returned by the OIDC Provider
  ctx.body = info;
  ctx.status = 200;
};
