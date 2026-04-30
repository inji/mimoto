package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import io.mosip.mimoto.dto.ErrorDTO;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.Valid;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Link transaction response containing transaction details and any errors.")
public class LinkTransactionResponseDto {

    @NotBlank(message = "Response time is required and cannot be blank")
    @Schema(description = "Response timestamp in ISO 8601 format", 
            example = "2026-04-08T12:00:00Z")
    private String responseTime;

    @NotNull(message = "Response is required")
    @Valid
    @Schema(description = "Link transaction response details")
    private LinkCodeResponse response;

    @Schema(description = "List of errors if any occurred during transaction linking", 
            example = "[]")
    private List<ErrorDTO> errors;
}
