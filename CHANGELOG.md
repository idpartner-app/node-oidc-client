2.1.0
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
