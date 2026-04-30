package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Data
@Setter
@Getter
@NoArgsConstructor
@Schema(description = "Request payload used to obtain or validate a secret key token for a client application.")
public class SecretKeyRequest {
    @Schema(description = "Client identifier requesting the secret key token.")
    public String clientId;
    @Schema(description = "Secret key associated with the client.")
    public String secretKey;
    @Schema(description = "Application identifier on whose behalf the token is requested.")
    public String appId;

    public SecretKeyRequest(String clientId, String secretKey, String appId) {
        this.clientId = clientId;
        this.secretKey = secretKey;
        this.appId = appId;
    }
}
