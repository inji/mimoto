package io.mosip.mimoto.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.mosip.mimoto.dto.deserializer.SelectedCredentialsDeserializer;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import io.mosip.mimoto.util.SelectedSdClaimsMergeUtil;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for submitting a presentation or rejecting a verifier")
public class SubmitPresentationRequestDTO {

    @Schema(description = "Draft-23: credential ID strings. DCQL: objects with queryId + selectedCredentialIds.")
    @JsonDeserialize(using = SelectedCredentialsDeserializer.class)
    private SelectedCredentials selectedCredentials;

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
        boolean hasErrorFields = (errorCode != null && !errorCode.trim().isEmpty())
                || (errorMessage != null && !errorMessage.trim().isEmpty());
        return hasCredentials && !hasErrorFields;
    }

    /**
     * Returns {@code true} when {@code selectedCredentials} uses the DCQL format
     * (objects with {@code queryId} and {@code selectedCredentialIds} per query).
     * Used to branch submission logic between DCQL and Draft-23 presentation flows.
     */
    public boolean isDcqlSubmission() {
        return selectedCredentials != null && selectedCredentials.isDcql();
    }

    /**
     * Returns the flat list of credential IDs for Draft-23 submissions
     * ({@code ["cred-id-1", "cred-id-2"]}). Returns {@code null} for DCQL submissions.
     */
    public List<String> getSelectedCredentialIds() {
        return selectedCredentials == null ? null : selectedCredentials.getCredentialIds();
    }

    /**
     * Returns per-query credential selections for DCQL submissions
     * ({@code [{queryId, selectedCredentialIds, ...}]}). Returns {@code null} for Draft-23 submissions.
     */
    public List<DcqlCredentialSelection> getDcqlSelections() {
        return selectedCredentials == null ? null : selectedCredentials.getDcqlSelections();
    }

    /**
     * Unions top-level {@code selectedSdClaims} with any nested inside DCQL selection objects,
     * combining disclosure paths per credential ID.
     */
    public Map<String, List<String>> resolveEffectiveSelectedSdClaims() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsMergeUtil.mergeInto(merged, selectedSdClaims);
        if (isDcqlSubmission()) {
            for (DcqlCredentialSelection selection : getDcqlSelections()) {
                SelectedSdClaimsMergeUtil.mergeInto(merged, selection.getSelectedSdClaims());
            }
        }
        return merged.isEmpty() ? null : merged;
    }

    /**
     * Checks if this is a rejection request (has error code and message, NO credentials, NO SD-claim selections)
     */
    public boolean isRejectionRequest() {
        boolean hasErrorFields = errorCode != null && !errorCode.trim().isEmpty()
                && errorMessage != null && !errorMessage.trim().isEmpty();
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasSdClaims = resolveEffectiveSelectedSdClaims() != null;
        return hasErrorFields && !hasCredentials && !hasSdClaims;
    }
}
