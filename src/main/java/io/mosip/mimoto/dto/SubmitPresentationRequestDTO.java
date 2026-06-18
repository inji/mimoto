package io.mosip.mimoto.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.mosip.mimoto.dto.deserializer.SelectedCredentialsDeserializer;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @Schema(description = "Selected SD-JWT claim paths per credential ID (SD-JWT credentials only)")
    private Map<String, List<String>> selectedSdClaims;

    private String errorCode;
    private String errorMessage;

    public boolean isSubmissionRequest() {
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasErrorFields = (errorCode != null && !errorCode.trim().isEmpty())
                || (errorMessage != null && !errorMessage.trim().isEmpty());
        return hasCredentials && !hasErrorFields;
    }

    public boolean isDcqlSubmission() {
        return selectedCredentials != null && selectedCredentials.isDcql();
    }

    public List<String> getSelectedCredentialIds() {
        return selectedCredentials == null ? null : selectedCredentials.getCredentialIds();
    }

    public List<DcqlCredentialSelection> getDcqlSelections() {
        return selectedCredentials == null ? null : selectedCredentials.getDcqlSelections();
    }

    /**
     * Merges top-level {@code selectedSdClaims} with any nested inside DCQL selection objects.
     */
    public Map<String, List<String>> resolveEffectiveSelectedSdClaims() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        if (selectedSdClaims != null) {
            merged.putAll(selectedSdClaims);
        }
        if (isDcqlSubmission()) {
            for (DcqlCredentialSelection selection : getDcqlSelections()) {
                if (selection.getSelectedSdClaims() != null) {
                    merged.putAll(selection.getSelectedSdClaims());
                }
            }
        }
        return merged.isEmpty() ? null : merged;
    }

    public boolean isRejectionRequest() {
        boolean hasErrorFields = errorCode != null && !errorCode.trim().isEmpty()
                && errorMessage != null && !errorMessage.trim().isEmpty();
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasSdClaims = resolveEffectiveSelectedSdClaims() != null;
        return hasErrorFields && !hasCredentials && !hasSdClaims;
    }
}
