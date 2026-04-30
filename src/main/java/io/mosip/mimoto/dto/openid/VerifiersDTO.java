package io.mosip.mimoto.dto.openid;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Response containing the trusted verifiers known to Mimoto for presentation flows.")
public class VerifiersDTO {
    @Schema(description = "List of trusted verifiers that can request verifiable presentations.")
    List<VerifierDTO> verifiers;
}
