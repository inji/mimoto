package io.mosip.mimoto.exception;

import io.mosip.mimoto.util.DPoPResponseHelper;
import lombok.Getter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;

/**
 * Raised when an issuer responds with a DPoP nonce challenge. Mimoto retries once internally.
 */
@Getter
public class DPoPChallengeException extends RuntimeException {

    private final HttpStatusCode statusCode;
    private final HttpHeaders responseHeaders;
    private final String responseBody;

    public DPoPChallengeException(HttpStatusCode statusCode, HttpHeaders responseHeaders, String responseBody) {
        super("DPoP nonce challenge from credential issuer");
        this.statusCode = statusCode;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;
    }

    public String getNonce() {
        return DPoPResponseHelper.dPoPNonce(responseHeaders);
    }
}
