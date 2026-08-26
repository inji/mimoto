package io.mosip.mimoto.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses {@code WWW-Authenticate} challenges for DPoP vs Bearer credential retry logic (RFC 9449 §7.2).
 */
public final class WwwAuthenticateChallenge {

    private static final Pattern ERROR_PATTERN =
            Pattern.compile("error\\s*=\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern DPOP_SCHEME_PATTERN =
            Pattern.compile("(^|,|\\s)DPoP(\\s|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BEARER_SCHEME_PATTERN =
            Pattern.compile("(^|,|\\s)Bearer(\\s|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern DPOP_SEGMENT_PATTERN =
            Pattern.compile("DPoP\\b.*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private final boolean dpop;
    private final boolean bearer;
    private final String error;

    private WwwAuthenticateChallenge(boolean dpop, boolean bearer, String error) {
        this.dpop = dpop;
        this.bearer = bearer;
        this.error = error;
    }

    public boolean isDpop() {
        return dpop;
    }

    public boolean isBearer() {
        return bearer;
    }

    public String getError() {
        return error;
    }

    public static WwwAuthenticateChallenge parse(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return new WwwAuthenticateChallenge(false, false, null);
        }

        boolean isDpop = DPOP_SCHEME_PATTERN.matcher(headerValue).find();
        boolean isBearer = BEARER_SCHEME_PATTERN.matcher(headerValue).find();

        String errorSource = headerValue;
        if (isDpop) {
            Matcher segmentMatcher = DPOP_SEGMENT_PATTERN.matcher(headerValue);
            if (segmentMatcher.find()) {
                errorSource = segmentMatcher.group();
            }
        }

        Matcher errorMatcher = ERROR_PATTERN.matcher(errorSource);
        String error = errorMatcher.find() ? errorMatcher.group(1) : null;

        return new WwwAuthenticateChallenge(isDpop, isBearer, error);
    }
}
