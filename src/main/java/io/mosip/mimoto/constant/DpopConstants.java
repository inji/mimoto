package io.mosip.mimoto.constant;

public final class DpopConstants {

    public static final String DPOP_HEADER = "DPoP";
    public static final String OAUTH_STATE_HEADER = "state";
    public static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    public static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String BEARER_TOKEN_TYPE = "Bearer";
    public static final String USE_DPOP_NONCE_ERROR = "use_dpop_nonce";
    public static final String INVALID_TOKEN_ERROR = "invalid_token";
    public static final String INVALID_DPOP_PROOF_ERROR = "invalid_dpop_proof";
    public static final String DPOP_BOUND_TOKEN_MESSAGE = "DPoP-bound access token";
    public static final String CERTIFY_DPOP_NOT_SUPPORTED_MESSAGE = "DPoP tokens are not supported. Use a Bearer token.";

    private DpopConstants() {
    }
}