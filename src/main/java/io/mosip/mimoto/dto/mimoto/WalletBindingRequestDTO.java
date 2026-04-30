package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@Schema(description = "Wallet binding request wrapper containing timestamp and binding details.")
public class WalletBindingRequestDTO {

    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request time of the wallet binding in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String requestTime;
    
    @NotNull(message = "Request details are required")
    @Valid
    @Schema(description = "Wallet binding request details")
    private WalletBindingInnerReq request;
}
