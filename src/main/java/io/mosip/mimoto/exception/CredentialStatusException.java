package io.mosip.mimoto.exception;

public class CredentialStatusException extends VCVerificationException {

    private static final long serialVersionUID = 4120357894122760813L;

    private final boolean expired;

    public CredentialStatusException(ErrorConstants error) {
        this(error, false);
    }

    public CredentialStatusException(ErrorConstants error, boolean expired) {
        super(error.getErrorCode(), error.getErrorMessage());
        this.expired = expired;
    }

    public CredentialStatusException(ErrorConstants error, String detail) {
        this(error, detail, false);
    }

    public CredentialStatusException(ErrorConstants error, String detail, boolean expired) {
        super(error.getErrorCode(), error.getErrorMessage() + " (" + detail + ")");
        this.expired = expired;
    }

    public boolean isExpired() {
        return expired;
    }
}
