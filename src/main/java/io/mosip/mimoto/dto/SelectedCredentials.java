package io.mosip.mimoto.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.mosip.mimoto.dto.deserializer.SelectedCredentialsDeserializer;
import io.mosip.mimoto.dto.serializer.SelectedCredentialsSerializer;
import lombok.Getter;

import java.util.List;

/**
 * Polymorphic holder for {@code selectedCredentials} in submit requests:
 * <ul>
 *   <li>Draft-23: {@code ["cred-id-1", "cred-id-2"]}</li>
 *   <li>DCQL: {@code [{"queryId":"q1","selectedCredentialIds":["cred-id-1"]}]}</li>
 * </ul>
 */
@Getter
@JsonDeserialize(using = SelectedCredentialsDeserializer.class)
@JsonSerialize(using = SelectedCredentialsSerializer.class)
public class SelectedCredentials {

    private final List<String> credentialIds;
    private final List<DcqlCredentialSelection> dcqlSelections;

    private SelectedCredentials(List<String> credentialIds, List<DcqlCredentialSelection> dcqlSelections) {
        if (credentialIds != null && dcqlSelections != null) {
            throw new IllegalArgumentException(
                    "selectedCredentials must be either credential ID strings or DCQL selection objects, not both");
        }
        this.credentialIds = credentialIds;
        this.dcqlSelections = dcqlSelections;
    }

    public static SelectedCredentials ofStrings(List<String> ids) {
        return new SelectedCredentials(ids, null);
    }

    public static SelectedCredentials ofDcql(List<DcqlCredentialSelection> selections) {
        return new SelectedCredentials(null, selections);
    }

    /**
     * {@code true} when the payload uses the DCQL selection shape (non-empty objects, no string IDs).
     */
    public boolean isDcql() {
        return dcqlSelections != null
                && !dcqlSelections.isEmpty()
                && (credentialIds == null || credentialIds.isEmpty());
    }

    public boolean isEmpty() {
        if (isDcql()) {
            return dcqlSelections.isEmpty();
        }
        return credentialIds == null || credentialIds.isEmpty();
    }
}
