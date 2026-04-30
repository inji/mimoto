package io.mosip.mimoto.dto;

import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.model.CredentialMetadata;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;

/**
 * DTO that contains decrypted credential data for session caching.
 * This avoids the need to decrypt credentials multiple times.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Cached representation of a decrypted credential and its related metadata.")
public class DecryptedCredentialDTO implements Serializable {

    /**
     * The credential ID from the original VerifiableCredential.
     */
    @Schema(description = "Credential identifier from the original stored verifiable credential.")
    private String id;

    /**
     * The wallet ID from the original VerifiableCredential.
     */
    @Schema(description = "Wallet identifier to which the credential belongs.")
    private String walletId;

    /**
     * The decrypted credential data as VCCredentialResponse.
     */
    @Schema(description = "Decrypted credential payload in wallet-consumable format.")
    private VCCredentialResponse credential;

    /**
     * The credential metadata from the original VerifiableCredential.
     */
    @Schema(description = "Metadata describing issuer and credential type.")
    private CredentialMetadata credentialMetadata;

    /**
     * The creation timestamp from the original VerifiableCredential.
     */
    @Schema(description = "Timestamp at which the credential record was created.")
    private Instant createdAt;

    /**
     * The update timestamp from the original VerifiableCredential.
     */
    @Schema(description = "Timestamp at which the credential record was last updated.")
    private Instant updatedAt;
}
