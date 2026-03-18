package io.mosip.mimoto.exception;

import io.mosip.mimoto.model.WalletLockStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorConstants {

    INVALID_REQUEST("invalid_request", "Some incorrect parameters in the request"),
    UNSUPPORTED_FORMAT("unsupported_format", "No VC of this format is found"),
    RESOURCE_NOT_FOUND("resource_not_found", "The requested resource doesn’t exist."),
    SERVER_UNAVAILABLE("server_unavailable", "The server is not reachable right now."),
    RESOURCE_EXPIRED("resource_expired", "The requested resource expired."),
    RESOURCE_INVALID("invalid_resource", "The requested resource is invalid."),
    REQUEST_TIMED_OUT("request_timed_out", "We are unable to process your request right now"),
    URI_TOO_LONG("uri_too_long", "Resource URI is too long to be handled"),
    INVALID_CLIENT("invalid_client", "The requested client doesn’t match."),
    INVALID_REDIRECT_URI("invalid_redirect_uri", "The requested redirect uri doesn’t match."),
    INVALID_RESPONSE_URI("invalid_response_uri", "The requested response uri doesn’t match."),
    INTERNAL_SERVER_ERROR("internal_server_error", "We are unable to process request now"),

    PROOF_TYPE_NOT_SUPPORTED_EXCEPTION("proof_type_not_supported", "Proof Type available in received credentials is not matching with supported proof terms"),
    SIGNATURE_VERIFICATION_EXCEPTION("signature_verification_failed", "Error while doing signature verification"),
    JSON_PARSING_EXCEPTION("json_parsing_failed", "Given data couldn't be parsed to JSON string"),
    UNKNOWN_EXCEPTION("unknown_exception", "Error while doing verification of verifiable credential"),
    PROOF_DOCUMENT_NOT_FOUND_EXCEPTION("proof_document_not_found", "Proof document is not available in the received credentials"),
    PUBLIC_KEY_NOT_FOUND_EXCEPTION("public_key_not_found", "Proof document is not available in the received credentials"),
    OAUTH2_AUTHENTICATION_EXCEPTION("user_authentication_error", "Failed to authenticate user via OAuth Identity Provider during login"),
    LOGIN_SESSION_INVALIDATE_EXCEPTION("user_logout_error", "Exception occurred when invalidating the session of a user"),
    SESSION_EXPIRED_OR_INVALID("session_invalid_or_expired", "User session is missing or expired. Please log in again."),
    DATABASE_CONNECTION_EXCEPTION("database_unavailable", "Failed to connect to the database"),
    REDIS_CONNECTION_EXCEPTION("redis_unavailable", "Failed to connect to the redis"),
    ENCRYPTION_FAILED("encryption_failed", "Failed to encrypt the data"),
    DECRYPTION_FAILED("decryption_failed", "Failed to decrypt the data"),
    SCHEMA_MISMATCH("schema_mismatch", "Failed to restored the stored data"),
    INVALID_USER("invalid_user", "User does not exist in database"),
    CREDENTIAL_DOWNLOAD_EXCEPTION("credential_download_error", "Failed to download and store the credential"),
    CREDENTIAL_FETCH_EXCEPTION("credential_fetch_error", "Failed to fetch the credential"),

    UNAUTHORIZED_ACCESS("unauthorized", "You are not authorized to access this resource"),
    WALLET_LOCKED("wallet_locked", "Wallet is locked"),
    INVALID_PIN("invalid_pin", "Invalid PIN or wallet key provided"),
    WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT.getValue(),"Incorrect passcode. Last attempt remaining before your Wallet is permanently locked"),
    WALLET_TEMPORARILY_LOCKED(WalletLockStatus.TEMPORARILY_LOCKED.getValue(), "You’ve reached the maximum number of attempts. Your wallet is now temporarily locked"),
    WALLET_PERMANENTLY_LOCKED(WalletLockStatus.PERMANENTLY_LOCKED.getValue(), "Your wallet has been permanently locked due to multiple failed attempts. Please click on forgot password to reset your wallet to continue"),

    WALLET_CREATE_VP_EXCEPTION("wallet_vp_creation_failed", "Failed to create Verifiable Presentation and store the details in session cache for the Wallet"),
    DUPLICATE_VERIFIER("duplicate_verifier", "This verifier is already trusted."),
    ERROR_ADDING_TRUSTED_VERIFIER("error", "Failed to add trusted verifier"),
    REJECT_VERIFIER_EXCEPTION("error", "Failed to submit Verifiable Presentation."),
    REJECTED_VERIFIER("success", "Presentation request rejected. An OpenID4VP error response has been sent to the verifier."),
    JWT_SIGNING_ERROR("jwt_signing_error", "Failed to sign JWT token during presentation submission"),
    KEY_GENERATION_ERROR("key_generation_error", "Failed to generate or retrieve cryptographic key"),
    DECRYPTION_ERROR("decryption_error", "Failed to decrypt data");

    private final String errorCode;
    private final String errorMessage;

}
