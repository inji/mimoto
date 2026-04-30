package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "IDP request wrapper used to link a transaction using a previously issued link code.")
public class IdpLinkTransactionReqDto {

    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Timestamp at which the link transaction request was created, in ISO 8601 format.")
    private String requestTime;
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "Inner request payload containing the link code.")
    private IdpLinkCodeDto request;
}
