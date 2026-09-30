package io.mosip.mimoto.dto.resident;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service request payload used to lock one or more authentication factors for an individual.")
public class AuthLockRequestDTO {
    @Schema(description = "Transaction identifier used to track the authentication lock request.")
    private String transactionID;

    @Schema(description = "Type of individual identifier provided in the request.",
            allowableValues = {"UIN", "VID"})
    private String individualIdType = "UIN";

    @Schema(description = "Individual identifier for whom authentication factors should be locked.")
    private String individualId;

    @Schema(description = "One-time password used to authorize the authentication lock request.")
    private String otp;

    // Available: demo, bio-Finger, bio-Iris, bio-FACE
    @Schema(description = "Authentication factors to be locked for the individual.")
    private List<String> authType;
}
