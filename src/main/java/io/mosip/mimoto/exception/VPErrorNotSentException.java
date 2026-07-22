package io.mosip.mimoto.exception;

public class VPErrorNotSentException extends BaseUncheckedException {

    private static final long serialVersionUID = -5350213197226295789L;


    /**
     * Constructor with errorCode, and errorMessage
     *
     * @param errorCode    The error code for this exception
     * @param errorMessage The error message for this exception
     */
    public VPErrorNotSentException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }

    public VPErrorNotSentException(String errorMessage) {
        super(ErrorConstants.REJECT_VERIFIER_EXCEPTION.getErrorCode(), errorMessage);
    }

    public VPErrorNotSentException(String errorMessage, Throwable cause) {
        super(ErrorConstants.REJECT_VERIFIER_EXCEPTION.getErrorCode(), errorMessage, cause);
    }
}
