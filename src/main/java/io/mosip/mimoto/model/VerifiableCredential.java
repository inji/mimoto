package io.mosip.mimoto.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "verifiable_credentials")
@Getter
@Setter
public class VerifiableCredential {

    @Id
    @Column(length = 36, updatable = false, nullable = false)
    private String id;

    @Column(name = "wallet_id", nullable = false)
    private String walletId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String credential;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private CredentialMetadata credentialMetadata;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "status_checks", columnDefinition = "jsonb")
    private List<CredentialStatusCheck> statusChecks;

    @Column(name = "status_last_checked_at", nullable = false)
    private Instant statusLastCheckedAt;

    @Column(name = "is_expired")
    private Boolean expired;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
