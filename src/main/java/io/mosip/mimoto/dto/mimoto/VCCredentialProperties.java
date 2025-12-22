package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

@Data
@JsonPropertyOrder({"@context", "credentialSubject", "validUntil", "id", "validFrom", "issuer", "proof", "type", "issuanceDate", "expirationDate"})
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VCCredentialProperties implements Serializable {
    private String issuer;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String validFrom;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String issuanceDate;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String validUntil;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String expirationDate;

    private VCCredentialResponseProof proof;

    private Map<String, Object> credentialSubject;

    @JsonProperty("@context")
    private Object context;

    @NotEmpty
    private List<@NotBlank String> type;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Map<String, Object> credentialStatus;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object renderMethod;
}
