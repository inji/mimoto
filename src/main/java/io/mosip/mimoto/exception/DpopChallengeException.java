package io.mosip.mimoto.exception;

import lombok.Getter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;

/**
 * Raised when an issuer responds with a DPoP nonce challenge that the browser must satisfy.
 */
@Getter
public class DpopChallengeException extends RuntimeException {

    private final HttpStatusCode statusCode;
    private final HttpHeaders responseHeaders;
    private final String responseBody;

    public DpopChallengeException(HttpStatusCode statusCode, HttpHeaders responseHeaders, String responseBody) {
        super("DPoP nonce challenge from credential issuer");
        this.statusCode = statusCode;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;
    }
}
