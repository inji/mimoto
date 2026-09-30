package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Authentication factor configuration specifying the type and count of factors required.")
public class AuthFactorDto {

    @NotBlank(message = "Type is required and cannot be blank")
    @Schema(description = "Type of authentication factor (e.g., PIN, BIOMETRIC, etc.)", 
            example = "BIOMETRIC")
    private String type;
    
    @NotNull(message = "Count is required")
    @Schema(description = "Number of authentication factors required", 
            example = "1")
    private Integer count;
    
    @Schema(description = "List of subtypes for the authentication factor", 
            example = "[\"FINGERPRINT\", \"FACE\"]")
    private List<String> subTypes;
}
