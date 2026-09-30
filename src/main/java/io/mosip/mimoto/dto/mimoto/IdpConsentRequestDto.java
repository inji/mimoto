package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Inner consent payload specifying the linked transaction and the claims or scopes approved by the user.")
public class IdpConsentRequestDto {
    @NotBlank(message = "Linked transaction ID is required and cannot be blank")
    @Schema(description = "Linked transaction identifier associated with the consent request.")
    private String linkedTransactionId;
    @Schema(description = "Claims approved by the user for disclosure.")
    private List<String> acceptedClaims;
    @Schema(description = "Authorization scopes approved by the user.")
    private List<String> permittedAuthorizeScopes;
}
