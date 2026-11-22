package io.mosip.mimoto.exception;

public class CredentialStatusException extends VCVerificationException {

    private static final long serialVersionUID = 4120357894122760813L;

    public CredentialStatusException(ErrorConstants error) {
        super(error.getErrorCode(), error.getErrorMessage());
    }

    public CredentialStatusException(ErrorConstants error, String detail) {
        super(error.getErrorCode(), error.getErrorMessage() + " (" + detail + ")");
    }
}
