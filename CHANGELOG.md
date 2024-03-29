5.0.0
- Make account selector URL fully customizable

4.0.0
- Add support for sending extra authorization params to the OP

3.1.3
- Bump up jose-wrapper library

3.1.2
- Bump up internal libraries

3.1.1
- Use @idpartner/jose-wrapper lib instead of node-jose

3.1.0
- Add support for paymet processing (beta)

3.0.6
- Always sends response_mode jwt, due to FAPI 1.0 AF

3.0.5
- Add claims parameter support

3.0.4
- Bump up openid-client lib

3.0.3
- Fix credential method by calling the absolute credential URL

3.0.2
- remove tls_client_certificate_bound_access_token from the default config. Force it to true for tls_client_auth auth methods

3.0.1
- Add tls_client_auth for payment details endpoint

3.0.0
- Add support for tls_client_auth and keep support for both client_secret_basic (default) and private_key_jwt (legacy)

2.0.0
- Add support for client-secret and preserve the jwt old usage (bumping up the major version)

1.5.0
- Revert of https://github.com/idpartner-app/node-oidc-client/pull/18

1.4.0
- Add support for client-secret and preserve the jwt old usage

1.3.2
- Not use default response in payments_details endpoint

1.3.1
- Handle payment_details_endpoint http code 204

1.3.0
- Include payments_info endpoint

1.2.1
- Bump up @idpartner/http-client from 1.2.0 to 1.2.1

1.2.0
- Add refreshToken, userInfo and basicUserInfo functions to support async flows

1.1.0
- Change claims method to return the tokenSet instead
- Bump up libraries
- Add new credential method to use the credential endpoint for verifiable credential issuance

1.0.3
- Bump up openid-client lib
- Provide timeout parameter for client's configuration

1.0.2
- Forward scope to account selection if no issuer selected

1.0.1
- Forward idpartner_token to the OP within the request object

1.0.0
- Remove idpartner signature verification
- Implement PAR in authorization flow
- Redirect to account selection if no issuer selected
- Rename config attribute from oidc_proxy_service_url to account_selector_service_url
- Remove config attribute trust_directory_service_url

0.1.4
- Removing unused controller.js file

0.1.3
- Bumping dependencies

0.1.2
- Modify default configuration to point to the correct prod urls
