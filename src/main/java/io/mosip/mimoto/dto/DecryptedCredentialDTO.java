package io.mosip.mimoto.dto;

import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.model.CredentialMetadata;
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
public class DecryptedCredentialDTO implements Serializable {

    /**
     * The credential ID from the original VerifiableCredential.
     */
    private String id;

    /**
     * The wallet ID from the original VerifiableCredential.
     */
    private String walletId;

    /**
     * The decrypted credential data as VCCredentialResponse.
     */
    private VCCredentialResponse credential;

    /**
     * The credential metadata from the original VerifiableCredential.
     */
    private CredentialMetadata credentialMetadata;

    /**
     * The creation timestamp from the original VerifiableCredential.
     */
    private Instant createdAt;

    /**
     * The update timestamp from the original VerifiableCredential.
     */
    private Instant updatedAt;

    /**
     * InputDescriptor.id (Draft-23) or DCQL CredentialQuery.id (OVP 1.0).
     * Bridge key from credential matching to VP submission.
     */
    private String identifier;
}
