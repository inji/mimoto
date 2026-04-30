package io.mosip.mimoto.util;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

/**
 * @author Mukul Puspam Class for logging description and message code
 */
@Data
@Getter
@Setter
public class LogDescription {
    /**
     * The description
     */
    private String message;
    /**
     * The message code
     */
    private String code;

    private String statusCode;
    /**
     * The status comment
     */
    private String statusComment;

    private String transactionStatusCode;

    private String subStatusCode;

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    @Override
    public String toString() {
        return this.getMessage();
    }

}
