package io.mosip.mimoto.constant;

public class SwaggerExampleConstants {

    public static final String ALL_PROPERTIES_EXAMPLE = """
            {
                "response": {
                    "modelDownloadMaxRetry": "10",
                    "audience": "ida-binding",
                    "datashare.host": "https://datashare-inji.collab.mosip.net",
                    "allowedInternalAuthType": "otp,bio-Finger,bio-Iris,bio-Face",
                    "openId4VCIDownloadVCTimeout": "30000",
                    "qr.code.height": "650",
                    "ovp.error.redirect.url.pattern": "%s?error=%s&error_description=%s",
                    "vcDownloadMaxRetry": "10",
                    "ovp.qrdata.pattern": "INJI_OVP://https://injiweb.collab.mosip.net/authorize?response_type=vp_token&resource=%s&presentation_definition=%s",
                    "minStorageRequiredForAuditEntry": "2",
                    "minStorageRequired": "2",
                    "keyPriorityOrder": "Ed25519,ES256K,ES256,RS256",
                    "vcDownloadPoolInterval": "6000",
                    "issuer": "residentapp",
                    "ovp.redirect.url.pattern": "%s#vp_token=%s&presentation_submission=%s",
                    "allowedAuthType": "demo,otp,bio-Finger,bio-Iris,bio-Face",
                    "allowedEkycAuthType": "demo,otp,bio-Finger,bio-Iris,bio-Face",
                    "warningDomainName": "https://api.collab.mosip.net",
                    "qr.code.width": "650",
                    "web.host": "https://injiweb.collab.mosip.net",
                    "web.redirect.url": "https://injiweb.collab.mosip.net/authorize",
                    "aboutInjiUrl": "https://docs.mosip.io/inji/inji-mobile-wallet/overview",
                    "qr.data.size.limit": "10000",
                    "faceSdkModelUrl": "https://api.collab.mosip.net/inji"
                },
                "errors": []
            }
            """;

    public static final String FETCH_USER_PROFILE_FROM_DB_SUCCESS = """
            {
                "display_name": "John Doe",
                "profile_picture_url": "https://example.com/profile.jpg",
                "email": "john.doe@example.com",
            }
            """;
    public static final String FETCH_USER_CACHE_PROFILE_SUCCESS = """
            {
                "display_name": "John Doe",
                "profile_picture_url": "https://example.com/profile.jpg",
                "email": "john.doe@example.com",
                "walletId": "123e4567-e89b-12d3-a456-426614174000"
            }
            """;

    public static final String FETCH_ALL_WALLETS_OF_USER_SUCCESS = """
            [
                {
                    "walletId": "123e4567-e89b-12d3-a456-426614174000"
                },
                {
                    "walletId": "223e4567-e89b-12d3-a456-426614174001"
                }
            ]
            """;

    public static final String FETCH_ALL_CREDENTIALS_OF_WALLET_SUCCESS = """
            [
                {
                    "issuer_name": "Mosip",
                    "issuer_logo": "https://example.com/logo.png",
                    "credential_type": "MosipVerifiableCredential",
                    "credential_type_logo": "https://example.com/credential-logo.png",
                    "credential_id": "1234567890"
                }
            ]
            """;
}
