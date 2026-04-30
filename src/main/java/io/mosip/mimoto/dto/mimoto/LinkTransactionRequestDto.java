package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import java.util.List;

@Data
@Schema(description = "Link transaction request containing code to link transactions.")
public class LinkTransactionRequestDto {
    
    @NotBlank(message = "Request time is required and cannot be blank")
    @Schema(description = "Request timestamp in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String requestTime;
    
    @NotBlank(message = "Link code is required and cannot be blank")
    @Schema(description = "Link code for transaction linking", 
            example = "LINK123456")
    private String linkCode;
}