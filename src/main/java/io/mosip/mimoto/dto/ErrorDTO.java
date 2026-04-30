package io.mosip.mimoto.dto;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonAlias;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

/**
 * Instantiates a new error DTO.
 *
 * @param errorcode the errorcode
 * @param message   the message
 *
 * @author Rishabh Keshari
 */
@Data
@Builder
@Schema(description = "Standard error payload returned by Mimoto and upstream integrations when a request cannot be processed.")
public class ErrorDTO implements Serializable {

    private static final long serialVersionUID = 2452990684776944908L;

    /** The errorcode. */
    @Schema(description = "It represents the type or category of the error",
            example = "invalid_request")
    @NotBlank(message = "errorCode is required")
    private String errorCode;

    @Schema(description = "A human-readable message providing more details about the error",
            example = "User ID cannot be null or empty")
    @NotBlank(message = "errorMessage is required")
    /** The message. */
    @JsonAlias("message")
    private String errorMessage;

    public ErrorDTO() {
    }

    public ErrorDTO(String errorCode, String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
