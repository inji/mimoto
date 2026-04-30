package io.mosip.mimoto.dto.resident;

import java.util.List;
import java.util.Map;

import io.mosip.mimoto.dto.ErrorDTO;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service OTP response containing the transaction details, masked delivery targets, and any upstream errors.")
public class OTPResponseDTO {

    @Schema(description = "Response identifier returned by the resident service.",
            example = "mosip.identity.otp.internal")
    private String id;

    @Schema(description = "Version of the resident OTP response contract.",
            example = "1.0")
    private String version;

    @Schema(description = "Transaction identifier associated with the OTP request.",
            example = "txn-7f3c52d8")
    private String transactionID;

    @Schema(description = "Timestamp at which the resident service generated the response.",
            example = "2026-04-27T10:15:31Z")
    private String responseTime;

    @Schema(description = "Errors returned by the resident service when OTP generation fails.")
    private List<ErrorDTO> errors;

    @Schema(description = "Masked contact details indicating where the OTP was delivered.")
    private OTPResponseMaskedDTO response;

    @Schema(description = "Optional metadata returned by the resident service.")
    private Map<String, Object> metadata;

}
