package io.mosip.mimoto.dto.pkce;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * Server-side PKCE state that must survive the browser redirect.
 * {@code redirectUri} is stored because authorize and token exchange are
 * separate HTTP requests.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PkceSession implements Serializable {

    public static final String CODE_CHALLENGE_METHOD = "S256";

    @Serial
    private static final long serialVersionUID = 1L;

    private String state;
    private String codeVerifier;
    private String codeChallenge;
    private String redirectUri;
}
