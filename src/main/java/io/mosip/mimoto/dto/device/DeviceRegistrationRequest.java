package io.mosip.mimoto.dto.device;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.mimoto.model.DevicePlatform;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Map;

@Schema(description = "Registers a wallet device key with a platform attestation bound to it")
public record DeviceRegistrationRequest(
        @Schema(description = "Attestation platform: ANDROID (Play Integrity) or IOS (App Attest)", example = "ANDROID") DevicePlatform platform,
        @Schema(description = "Nonce returned by GET /device/nonce") String nonce,
        @JsonProperty("public_key_jwk") @Schema(description = "Device public key as a JWK (EC P-256)") Map<String, Object> publicKeyJwk,
        @JsonProperty("integrity_token") @Schema(description = "Platform attestation requested with base64url(SHA-256(nonce + JWK thumbprint)): the Play Integrity token, or the base64 App Attest attestation object whose clientDataHash is SHA-256 of that value") String integrityToken) {
}
