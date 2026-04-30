package io.mosip.mimoto.dto.resident;

import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service OTP request payload used to generate an OTP for a given individual identifier.")
public class OTPRequestDTO {

    @Schema(description = "Request identifier used by the resident service.",
            example = "mosip.resident.otp")
    private String id;

    @Schema(description = "Version of the resident OTP request contract.",
            example = "v1")
    private String version;

    @Schema(description = "Transaction identifier used to track the OTP request across systems.")
    private String transactionID;

    @Schema(description = "Timestamp at which the OTP request was created, in ISO 8601 format.")
    private String requestTime;

    @Schema(description = "Individual identifier, such as UIN or VID, for which the OTP is requested.")
    private String individualId;

    @Schema(description = "Type of individual identifier provided in the request.",
            allowableValues = {"UIN", "VID"})
    private String individualIdType;

    @Schema(description = "Delivery channels through which the OTP should be sent.",
            allowableValues = {"EMAIL", "PHONE", "SMS"})
    private List<String> otpChannel;

    @Schema(description = "Optional metadata supplied along with the OTP request.")
    private Map<String, Object> metadata;

}
