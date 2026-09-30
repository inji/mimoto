package io.mosip.mimoto.dto.dpop;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * Server-side DPoP state that must survive the browser redirect.
 * PKCE lives in {@code PkceSession}, stored under a separate HTTP session attribute.
 * Access token, {@code jkt}, and credential {@code htu} are not stored; they
 * are passed or computed at proof time. Credential {@code htu} and
 * {@code issuerId} come from the download request and issuer well-known.
 * Token {@code htu} is stored so the token proof stays bound to the
 * authorization-server token endpoint.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DPoPSession implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String state;
    private String alg;
    private String jwkJson;
    private String tokenHtu;
    private String issuerDPoPNonce;
}
