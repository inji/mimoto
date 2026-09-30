package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
@Schema(description = "Combined authentication and consent request payload used in IDP flows.")
public class AuthAndConsentRequestDto {
    @NotBlank(message = "Linked transaction ID is required and cannot be blank")
    @Schema(description = "Linked transaction identifier associated with the authentication and consent request.")
    private String linkedTransactionId;

    @NotBlank(message = "Individual ID is required and cannot be blank")
    @Schema(description = "Individual identifier participating in the request.")
    private String individualId;

    @Schema(description = "Claims accepted by the user for disclosure.")
    private List<String> acceptedClaims;

    @Schema(description = "Authorization scopes permitted by the user.")
    private List<String> permittedAuthorizeScopes;

    @NotEmpty(message = "Challenge list cannot be empty")
    @Valid
    @Schema(description = "Challenge list that must be satisfied for authentication.")
    private List<IdpAuthChallangeDto> challengeList;
}
