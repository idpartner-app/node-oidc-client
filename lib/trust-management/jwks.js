import jose from 'node-jose';
import { httpClient } from './http-client';

// TODO: Add caching to avoid hitting issuer URL all the time
const fetchJWKs = async () => {
  // Get all jwks from public endpoint.
  const response = await httpClient.get(`/jwks`);
  const { data: jwks } = response;
  return jwks;
};

export const getKeyStore = async () => {
  const JWKs = await fetchJWKs();
  return jose.JWK.asKeyStore(JWKs);
};
