package io.mosip.mimoto.dto.resident;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service request payload used to unlock one or more authentication factors for an individual.")
public class AuthUnlockRequestDTO {
    @Schema(description = "Transaction identifier used to track the authentication unlock request.")
    private String transactionID;

    @Schema(description = "Type of individual identifier provided in the request.",
            allowableValues = {"UIN", "VID"})
    private String individualIdType = "UIN";

    @Schema(description = "Individual identifier for whom authentication factors should be unlocked.")
    private String individualId;

    @Schema(description = "One-time password used to authorize the authentication unlock request.")
    private String otp;

    // Available: demo, bio-Finger, bio-Iris, bio-FACE
    @Schema(description = "Authentication factors to be unlocked for the individual.")
    private List<String> authType;

    @Schema(description = "Duration in seconds for which the unlock should remain effective.",
            example = "0")
    private String unlockForSeconds = "0";
}
