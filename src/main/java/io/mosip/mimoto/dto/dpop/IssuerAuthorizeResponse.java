package io.mosip.mimoto.dto.dpop;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "OpenID4VCI authorization URL built by Mimoto, including dpop_jkt.")
public class IssuerAuthorizeResponse {

    @Schema(description = "Authorization Server URL. Inji Web should open this URL.",
            example = "https://as.example.com/authorize?client_id=...&dpop_jkt=...")
    private String authorizationUrl;
}
