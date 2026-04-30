package io.mosip.mimoto.dto.resident;

import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service credential issuance request payload.")
public class CredentialRequestDTO {
    @Schema(description = "Individual identifier for whom the credential should be issued.")
    private String individualId;

    @Schema(description = "One-time password used to authorize credential issuance.")
    private String otp;

    @Schema(description = "Transaction identifier used to track the credential issuance request.")
    private String transactionID;

    @Schema(description = "Credential type requested from the resident service.")
    private String credentialType;

    @Schema(description = "Flag indicating whether the credential response should be encrypted.",
            example = "false")
    private Boolean encrypt = false;

    @Schema(description = "Public encryption key used when encrypted credential delivery is requested.")
    private String encryptionKey;

    @Schema(description = "Issuer identifier to be embedded in or associated with the credential request.")
    private String issuer;

    @Schema(description = "Recipient identifier for whom the credential is intended.")
    private String recepiant;

    @Schema(description = "User identifier or username associated with the credential request.")
    private String user;

    @Schema(description = "Additional key-value pairs supplied to the resident service along with the request.")
    private Map<String, Object> additionalData;

    @Schema(description = "List of credential attributes that may be shared in the issued credential.")
    private List<String> sharableAttributes;

    public void setIndividualId(String individualId) {
        this.individualId = individualId;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public void setTransactionID(String transactionID) {
        this.transactionID = transactionID;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setUser(String user) {
        this.user = user;
    }
}
