package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Schema(description = "Resident service OTP request payload used to fetch an individual identifier from an AID flow.")
public class IndividualIdOTPRequestDTO {

    @Schema(description = "Request identifier used by the resident service.",
            example = "mosip.resident.individualid.otp")
    private String id;

    @Schema(description = "Version of the individual ID OTP request contract.",
            example = "v1")
    private String version;

    @Schema(description = "Transaction identifier used to track the individual ID OTP request.")
    private String transactionId;

    @Schema(description = "Timestamp at which the individual ID OTP request was created, in ISO 8601 format.")
    private String requestTime;

    @Schema(description = "Delivery channels through which the OTP should be sent.",
            allowableValues = {"EMAIL", "PHONE", "SMS"})
    private List<String> otpChannel;

    @Schema(description = "Application identifier or account identifier for which the individual ID is being resolved.")
    private String individualId;

    @Schema(description = "Optional metadata supplied along with the individual ID OTP request.")
    private Map<String, Object> metadata;

}
