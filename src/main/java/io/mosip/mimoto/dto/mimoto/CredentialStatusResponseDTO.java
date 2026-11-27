package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.mimoto.model.CredentialStatusCheck;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatusResponseDTO {

    @Schema(description = "Unique identifier of the credential")
    private String credentialId;

    @Schema(description = "Status purposes recorded for the credential. valid=false means revoked or suspended for that purpose. Empty list when status has not been checked.")
    private List<CredentialStatusCheck> statusChecks;

    @Schema(description = "Time at which the credential status was last checked")
    private Instant lastCheckedAt;

    @JsonProperty("isExpired")
    @Schema(description = "Whether the credential was expired at the last check. Null when expiry has not been checked.")
    private Boolean expired;
}
