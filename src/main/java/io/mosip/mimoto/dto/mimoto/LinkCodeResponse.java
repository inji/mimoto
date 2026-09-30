package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Schema(description = "Response payload returned after generating or fetching a link code for IDP flows.")
public class LinkCodeResponse {
    @NotBlank(message = "Link transaction ID is required and cannot be blank")
    @Schema(description = "Linked transaction identifier associated with the link code.")
    private String linkTransactionId;
    @NotBlank(message = "Client name is required and cannot be blank")
    @Schema(description = "Display name of the client requesting authentication or consent.")
    private String clientName;
    @NotBlank(message = "Logo URL is required and cannot be blank")
    @Schema(description = "Logo URL of the requesting client.")
    private String logoUrl;
    @NotEmpty(message = "Auth factors cannot be empty")
    @Valid
    @Schema(description = "Nested list of authentication factor groups accepted for this transaction.")
    private List<List<AuthFactorDto>> authFactors;
    @Schema(description = "Authorization scopes requested by the client.")
    private List<String> authorizeScopes;
    @Schema(description = "Claims marked essential by the client.")
    private List<String> essentialClaims;
    @Schema(description = "Claims marked voluntary by the client.")
    private List<String> voluntaryClaims;
    @Schema(description = "Additional configuration values associated with the link-code transaction.")
    private Map<String, Object> configs;
}
