package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * DTO for submitting a presentation with selected credentials or rejecting a verifier
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for submitting a presentation with selected credentials or rejecting a verifier")
public class SubmitPresentationRequestDTO {

    @Schema(description = "List of credential IDs that the user has selected to include in the presentation", 
            example = "[\"cred-123\", \"cred-456\"]")
    private List<String> selectedCredentials;

    @Schema(description = "Selected SD-JWT claim paths per credential ID for selective disclosure (only for SD-JWT credentials)",
            example = "{\"cred-123\": [\"name\", \"dob\"]}")
    private Map<String, List<String>> selectedSdClaims;

    @Schema(description = "Error code for rejecting the verifier (used when user denies the presentation request)", 
            example = "access_denied")
    private String errorCode;

    @Schema(description = "Error message for rejecting the verifier (used when user denies the presentation request)", 
            example = "User denied authorization to share credentials")
    private String errorMessage;

    /**
     * Checks if this is a submission request (has selected credentials and NO error fields)
     */
    public boolean isSubmissionRequest() {
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasErrorFields = (errorCode != null && !errorCode.trim().isEmpty()) ||
                                 (errorMessage != null && !errorMessage.trim().isEmpty());
        return hasCredentials && !hasErrorFields;
    }

    /**
     * Checks if this is a rejection request (has error code and message, NO credentials, NO SD-claim selections)
     */
    public boolean isRejectionRequest() {
        boolean hasErrorFields = errorCode != null && !errorCode.trim().isEmpty() &&
                                errorMessage != null && !errorMessage.trim().isEmpty();
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasSdClaims = selectedSdClaims != null && !selectedSdClaims.isEmpty();
        return hasErrorFields && !hasCredentials && !hasSdClaims;
    }
}
