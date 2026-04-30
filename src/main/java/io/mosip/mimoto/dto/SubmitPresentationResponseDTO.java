package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Response returned after a presentation is submitted or rejected, including the processing status, message, and verifier redirect URI when available.")
public class SubmitPresentationResponseDTO {
    
    @NotBlank(message = "Status is required and cannot be blank")
    @Schema(description = "Outcome of the presentation submission workflow, such as success when credentials were sent or error when the request was rejected.",
            allowableValues = {"SUCCESS", "ERROR"},
            example = "SUCCESS")
    private String status;
    
    @Schema(description = "Verifier callback URI to which the wallet or client should redirect after the presentation flow is completed.",
            example = "https://verifier.example/callback")
    private String redirectUri;
    
    @NotBlank(message = "Message is required and cannot be blank")
    @Schema(description = "Human-readable summary explaining whether the presentation was submitted successfully or rejected by the user.",
            example = "Request processed successfully.")
    private String message;
}
