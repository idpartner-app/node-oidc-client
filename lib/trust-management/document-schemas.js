import joi from 'joi';

export const identityProviderSchema = joi.object({
  name: joi.string().required(),
  issuer_url: joi.string().uri().required(),
});
