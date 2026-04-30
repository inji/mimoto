package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "IDP link code request containing the code for linking transactions.")
public class IdpLinkCodeDto {
    
    @NotBlank(message = "Link code is required and cannot be blank")
    @Schema(description = "Link code for transaction linking", 
            example = "LINK123456")
    private String linkCode;
}
