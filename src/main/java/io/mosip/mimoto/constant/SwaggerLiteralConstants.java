package io.mosip.mimoto.constant;

public class SwaggerLiteralConstants {

    /* Attestation Controller */
    public static final String ATTESTATION_NAME = "Attestation";
    public static final String ATTESTATION_DESCRIPTION = "All the attestation related endpoints";

    /* Common Inji Controller */
    public static final String COMMON_INJI_NAME = "Inji Wallet Properties";
    public static final String COMMON_INJI_DESCRIPTION = "All endpoints related to Inji Wallet properties";
    public static final String COMMON_INJI_GET_PROPERTIES_SUMMARY = "Retrieve all Inji Wallet properties";
    public static final String COMMON_INJI_GET_PROPERTIES_DESCRIPTION = "This endpoint allow you to retrieve all the Inji Wallet properties";

    /* Credentials Controller */
    public static final String CREDENTIALS_NAME = "Credentials download using OpenId4VCI";
    public static final String CREDENTIALS_DESCRIPTION = "All the credentials related endpoints";
    public static final String CREDENTIALS_DOWNLOAD_VC_SUMMARY = "Download credentials as PDF";
    public static final String CREDENTIALS_DOWNLOAD_VC_DESCRIPTION = "This endpoint allow you to download the credentials as PDF";

    /* Credentials Share Controller */
    public static final String CREDENTIALS_SHARE_NAME = "Credential Share";
    public static final String CREDENTIALS_SHARE_DESCRIPTION = "All the credential download endpoints";
    public static final String CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_SUMMARY = "Notify through web sub once credential is downloaded";
    public static final String CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_DESCRIPTION = "This endpoint allow web sub to callback once the credential is issued";
    public static final String CREDENTIALS_SHARE_REQUEST_VC_SUMMARY = "request for credential issue";
    public static final String CREDENTIALS_SHARE_REQUEST_VC_DESCRIPTION = "This endpoint allow you to request for credential issue";
    public static final String CREDENTIALS_SHARE_REQUEST_VC_STATUS_SUMMARY = "polling for credential issue status";
    public static final String CREDENTIALS_SHARE_REQUEST_VC_STATUS_DESCRIPTION = "This endpoint allow you to poll for credential issue status";
    public static final String CREDENTIALS_SHARE_DOWNLOAD_VC_SUMMARY = "Download the credential using OTP Flow";
    public static final String CREDENTIALS_SHARE_DOWNLOAD_VC_DESCRIPTION = "This endpoint allow you to download credential issued";

    /* IDP Controller */
    public static final String IDP_NAME = "Wallet Binding";
    public static final String IDP_DESCRIPTION = "All the authorization related endpoints";
    public static final String IDP_BINDING_OTP_SUMMARY = "Invoke OTP request for wallet binding";
    public static final String IDP_BINDING_OTP_DESCRIPTION = "This endpoint allow you to invoke OTP for wallet binding";
    public static final String IDP_WALLET_BINDING_SUMMARY = "Wallet Binding";
    public static final String IDP_WALLET_BINDING_DESCRIPTION = "This endpoint allow you to perform the wallet binding";
    public static final String IDP_GET_TOKEN_SUMMARY = "Retrieve accessToken for OIDC flow";
    public static final String IDP_GET_TOKEN_DESCRIPTION = "This endpoint allow you to retrieve the access token in exchange for authorization code";

    /* Issuers Controller */
    public static final String ISSUERS_NAME = "Issuers";
    public static final String ISSUERS_DESCRIPTION = "All the issuers related endpoints";
    public static final String ISSUERS_GET_ISSUERS_SUMMARY = "Retrieve all onboarded issuers";
    public static final String ISSUERS_GET_ISSUERS_DESCRIPTION = "This endpoint allow you to retrieve all the onboarded issuers";
    public static final String ISSUERS_GET_SPECIFIC_ISSUER_SUMMARY = "Retrieve specific issuer's config";
    public static final String ISSUERS_GET_SPECIFIC_ISSUER_DESCRIPTION = "This endpoint allow you to retrieve the complete configuration of the specific issuer";
    public static final String ISSUERS_GET_ISSUER_WELLKNOWN_SUMMARY = "Retrieve specific issuer's well known";
    public static final String ISSUERS_GET_ISSUER_WELLKNOWN_DESCRIPTION = "This endpoint allow you to retrieve the well known of the specific issuer. Since version 0.16.0, this endpoint is deprecated and will be removed in a future release. Use issuers new endpoint issuers/{issuer-id}/configuration instead.";
    public static final String ISSUERS_GET_ISSUER_CONFIGURATION_SUMMARY = "Retrieve specific issuer's and its corresponding authorization server well-known config";
    public static final String ISSUERS_GET_ISSUER_CONFIGURATION_DESCRIPTION = "This endpoint allows you to retrieve the well-known configuration of a specific issuer and its corresponding authorization server";

    /* Prensentation Controller */
    public static final String PRESENTATION_NAME = "Presentation";
    public static final String PRESENTATION_DESCRIPTION = "All the online sharing related endpoints";
    public static final String PRESENTATION_AUTHORIZE_SUMMARY = "Perform the authorization";
    public static final String PRESENTATION_AUTHORIZE_DESCRIPTION = "This endpoint allow you to redirect the token back to the caller post authorization";

    /* Resident Service Controller */
    public static final String RESIDENT_NAME = "Resident Service";
    public static final String RESIDENT_DESCRIPTION = "All the resident service related endpoints";
    public static final String RESIDENT_REQUEST_OTP_SUMMARY = "Request for OTP";
    public static final String RESIDENT_REQUEST_OTP_DESCRIPTION = "This endpoint allow you to request OTP for credential download";
    public static final String RESIDENT_REQUEST_INDIVIDUALID_OTP_SUMMARY = "Request OTP for retrieving Individual Id";
    public static final String RESIDENT_REQUEST_INDIVIDUALID_OTP_DESCRIPTION = "This endpoint allow you to request OTP to retrieve Individual Id";
    public static final String RESIDENT_GET_INDIVIDUALID_SUMMARY = "Retrieve Individual Id using AID";
    public static final String RESIDENT_GET_INDIVIDUALID_DESCRIPTION = "This endpoint allow you to retrieve the Individual Id using AID";

    /* Verifiers Controller */
    public static final String VERIFIERS_NAME = "Verifiers";
    public static final String VERIFIERS_DESCRIPTION = "All the verifiers related endpoints";
    public static final String VERIFIERS_GET_VERIFIERS_SUMMARY = "Retrieve all trusted verifiers";
    public static final String VERIFIERS_GET_VERIFIERS_DESCRIPTION = "This endpoint allow you to retrieve all the trusted verifiers";

    /* Users Controller */
    public static final String USERS_NAME = "Users";
    public static final String USERS_DESCRIPTION = "All the User Profile related endpoints";

    /* Wallets Controller */
    public static final String RETRIEVE_ALL_WALLETS_SUMMARY = "Retrieve all wallets for the user";
    public static final String RETRIEVE_ALL_WALLETS_DESCRIPTION = "This API is secured using session-based authentication. The session ID is extracted from the Cookie header to authenticate the user. The user's ID is obtained from the session stored in Redis, and all wallets associated with the user are fetched from the database. If successful, the list of wallets is returned; otherwise, an appropriate error response is returned.";

    public static final String WALLETS_NAME = "Wallets";
    public static final String WALLETS_DESCRIPTION = "All the Wallet related endpoints";
    public static final String WALLETS_DELETE_SUMMARY = "Delete a Wallet";
    public static final String WALLETS_DELETE_DESCRIPTION = "This endpoint allows you to delete a specific wallet. The API is secured using session-based authentication. The session ID is extracted from the Cookie header to authenticate the user. The user's ID is obtained from the session and used to validate ownership of the Wallet before deletion. If the Wallet is successfully deleted, a 200 OK response is returned; otherwise, an appropriate error response is returned.";

    /* Wallet Credentials Controller */
    public static final String WALLET_CREDENTIALS_NAME = "Wallet Credentials";
    public static final String WALLET_CREDENTIALS_DESCRIPTION = "All the Wallet Credentials related endpoints";
    public static final String WALLET_CREDENTIALS_DELETE_SUMMARY = "Delete a credential from a wallet";
    public static final String WALLET_CREDENTIALS_DELETE_DESCRIPTION = "This endpoint allows you to delete a specific credential from a wallet";
    public static final String WALLET_CREDENTIALS_FETCH_ALL_SUMMARY = "Fetch all credentials for a wallet";
    public static final String WALLET_CREDENTIALS_FETCH_ALL_DESCRIPTION = "This endpoint allows you to retrieve all credentials for a specific wallet";

    /* OAuth2 ID Token Authentication Controller */
    public static final String ID_TOKEN_AUTHENTICATION_NAME = "OAuth2 ID Token Authentication";
    public static final String ID_TOKEN_AUTHENTICATION_DESCRIPTION = "All the OAuth2 ID Token Authentication related endpoints";

    /* Wallet Presentations Controller */
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUMMARY = "Processes Verifiable Presentation Authorization Request and provides details about the verifier and presentation.";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_DESCRIPTION = "This API is secured using session-based authentication. Upon receiving a request, the session is first retrieved using the session ID extracted from the Cookie header to authenticate the user. Once authenticated, the API processes the received Verifiable Presentation Authorization Request from the Verifier for a specific wallet. It validates the session, verifies the authenticity of the request, and checks if the Verifier is pre-registered and trusted by the wallet. If all validations pass, the API returns a response containing the presentation details; otherwise, an appropriate error response is returned.";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_REQ_EXAMPLE_NAME = "Verifier Verifiable Presentation Authorization Request";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_REQ_EXAMPLE_VALUE = "{ \"authorizationRequestUrl\": \"client_id=mock-client&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D\" }";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUCCESS_EXAMPLE_NAME = "Success response";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUCCESS_EXAMPLE_VALUE = "{ \"presentationId\": \"123e4567-e89b-12d3-a456-426614174000\", \"verifier\": { \"id\": \"mock-client\", \"name\": \"Requester name\", \"logo\": \"https://api.collab.mosip.net/inji/verifier-logo.png\", \"isTrusted\": true, \"isPreregisteredWithWallet\": true, \"redirectUri\": \"https://injiverify.collab.mosip.net/redirect\" } }";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_MISSING_RESPONSE_TYPE_NAME = "response_type is missing in Authorization request";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_MISSING_RESPONSE_TYPE_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Missing Input: response_type param is required\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_INVALID_WALLET_ID_NAME = "Invalid Wallet ID";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_INVALID_WALLET_ID_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_WALLET_LOCKED_NAME = "Wallet ID not found in session";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_WALLET_LOCKED_VALUE = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_401_USER_NOT_FOUND_NAME = "User ID is not present in session";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_401_USER_NOT_FOUND_VALUE = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_VERIFIERS_FETCH_FAILED_NAME = "Failed to fetch pre-registered trusted verifiers";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_VERIFIERS_FETCH_FAILED_VALUE = "{\"errorCode\": \"RESIDENT-APP-026\", \"errorMessage\": \"Api not accessible failure\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_SERVER_ERROR_NAME = "Unexpected Server Error";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_SERVER_ERROR_VALUE = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_INVALID_URI_SYNTAX_NAME = "Invalid URI syntax";
    public static final String WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_INVALID_URI_SYNTAX_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Incorrect URI parameters in the request\"}";

    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUMMARY = "Get matching credentials for a presentation request";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_DESCRIPTION = "This API retrieves credentials from the wallet that match the presentation definition requirements. It returns available credentials that can satisfy the presentation request along with any missing claims that are required but not available.";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUCCESS_EXAMPLE_NAME = "Success response";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUCCESS_EXAMPLE_VALUE = "{ \"availableCredentials\": [{ \"credentialId\": \"cred-123\", \"credentialTypeDisplayName\": \"W3C VC\", \"credentialTypeLogo\": \"https://mosip.github.io/inji-config/logos/mosipid-logo.png\", \"type\": [\"IDCredential\"], \"claims\": { \"birthdate\": \"1990-01-01\" } }], \"missingClaims\": [] }";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_INVALID_WALLET_ID_NAME = "Invalid Wallet ID";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_INVALID_WALLET_ID_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_PRESENTATION_NOT_FOUND_NAME = "Presentation not found";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_PRESENTATION_NOT_FOUND_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Presentation not found in session\"}";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_401_USER_NOT_FOUND_NAME = "User ID is not present in session";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_401_USER_NOT_FOUND_VALUE = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_500_SERVER_ERROR_NAME = "Unexpected Server Error";
    public static final String WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_500_SERVER_ERROR_VALUE = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}";

    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_SUMMARY = "Submit presentation or reject verifier";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_DESCRIPTION = "This API handles both presentation submission and verifier rejection based on the request content. For submission: include selectedCredentials array. For rejection: include errorCode and errorMessage fields.";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_SUBMIT_EXAMPLE_NAME = "Submit Presentation";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_SUBMIT_EXAMPLE_VALUE = "{ \"selectedCredentials\": [\"cred-123\", \"cred-456\"] }";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_REJECT_EXAMPLE_NAME = "Reject Verifier";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_REJECT_EXAMPLE_VALUE = "{ \"errorCode\": \"access_denied\", \"errorMessage\": \"User denied authorization to share credentials\" }";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_200_SUBMITTED_NAME = "Presentation submitted";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_200_SUBMITTED_VALUE = "{ \"presentationId\": \"presentation-123\", \"status\": \"SUCCESS\", \"message\": \"Presentation successfully submitted and shared with verifier\" }";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_200_REJECTED_NAME = "Verifier rejected";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_200_REJECTED_VALUE = "{\"status\": \"success\", \"message\": \"Presentation request rejected. An OpenID4VP error response has been sent to the verifier.\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_FORMAT_NAME = "Invalid request format";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_FORMAT_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Request must contain either selectedCredentials or both errorCode and errorMessage\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_WALLET_ID_NAME = "Invalid Wallet ID";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_WALLET_ID_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_PRESENTATION_NOT_FOUND_NAME = "Presentation not found";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_400_PRESENTATION_NOT_FOUND_VALUE = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Presentation not found in session\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_401_UNAUTHORIZED_NAME = "unauthorized";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_401_UNAUTHORIZED_VALUE = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User ID not found in session\"}";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_500_SERVER_ERROR_NAME = "Server error";
    public static final String WALLET_PRESENTATIONS_HANDLE_ACTION_500_SERVER_ERROR_VALUE = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}";
}
