package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service request payload used to generate a virtual ID for an individual.")
public class VIDGenerateRequestDTO {
    @Schema(description = "Type of virtual ID to generate.",
            allowableValues = {"TEMPORARY", "PERPETUAL"})
    private String vidType;

    @Schema(description = "Type of individual identifier provided for VID generation.",
            allowableValues = {"UIN", "VID"})
    private String individualIdType;

    @Schema(description = "Individual identifier, such as UIN or VID, for which the virtual ID should be generated.")
    private String individualId;

    @Schema(description = "One-time password used to authorize the virtual ID generation request.")
    private String otp;

    @Schema(description = "Transaction identifier used to track the virtual ID generation request.")
    private String transactionID;
}
