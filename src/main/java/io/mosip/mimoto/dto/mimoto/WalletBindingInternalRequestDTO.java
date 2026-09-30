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
@Schema(description = "Internal wallet binding request wrapper containing the request timestamp and normalized wallet binding payload.")
public class WalletBindingInternalRequestDTO {
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request Time of the Wallet Binding")
    private String requestTime;
    @NotNull(message = "Request body is required")
    @Valid
    @Schema(description = "Body of the Request")
    private WalletBindingInnerRequestDto request;

}
