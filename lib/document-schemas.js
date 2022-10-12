const joi = require('joi');

exports.identityProviderSchema = joi.object({
  name: joi.string().required(),
  issuer_url: joi.string().uri().required(),
});
