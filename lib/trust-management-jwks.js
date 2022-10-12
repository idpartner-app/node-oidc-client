const jose = require('node-jose');
const axios = require('axios');

const fetchJWKs = async config => {
  // Get all jwks from public endpoint.
  const { data: jwks } = await axios.get(`${config.trust_directory_service_url}/jwks`);
  return jwks;
};

exports.getKeyStore = async config => {
  const JWKs = await fetchJWKs(config);
  return jose.JWK.asKeyStore(JWKs);
};
