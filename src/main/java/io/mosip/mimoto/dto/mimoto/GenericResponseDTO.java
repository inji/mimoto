package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Generic acknowledgment response returned for callback or asynchronous processing APIs.")
public class GenericResponseDTO {
    
    @NotBlank(message = "Status is required and cannot be blank")
    @Schema(description = "Status of the operation after the request is processed.", 
            allowableValues = {"SUCCESS", "ERROR"},
            example = "SUCCESS")
    private String status;
    
    @NotBlank(message = "Message is required and cannot be blank")
    @Schema(description = "Human-readable message explaining the operation result or error.", 
            example = "Request processed successfully.")
    private String message;

    public void setStatus(String status) {
        this.status = status;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
