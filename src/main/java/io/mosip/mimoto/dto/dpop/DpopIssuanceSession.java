package io.mosip.mimoto.dto.dpop;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * Server-side DPoP issuance state. Bound to the HTTP session (cookie) and keyed by OAuth {@code state}.
 * Private JWK and access token never leave Mimoto.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DpopIssuanceSession implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String state;
    private String issuerId;
    private String alg;
    private String privateJwkJson;
    private String jkt;
    private String tokenHtu;
    private String credentialHtu;
    private String accessToken;
    private String tokenType;
    private String cNonce;
    private String asDpopNonce;
    private String issuerDpopNonce;
}
