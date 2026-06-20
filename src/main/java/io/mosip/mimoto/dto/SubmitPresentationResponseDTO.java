package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Response payload for successful response submission")
public class SubmitPresentationResponseDTO {
    @Schema(description = "Status of the presentation submission",
            example = "SUCCESS")
    private String status;
    @Schema(description = "Redirection URI to which the user-agent should be redirected after submission",
            example = "https://verifier.example.com/callback?state=af0ifjsldkj")
    private String redirectUri;
    @Schema(description = "Message indicating the result of the submission",
            example = "Presentation successfully submitted and shared with verifier")
    private String message;
}
