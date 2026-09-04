package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestResponseDTO;
import io.mosip.mimoto.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@ControllerAdvice
@ResponseBody
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(Throwable.class)  // Catch-all for unexpected exceptions
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorDTO handleGenericException(Exception ex) {
        log.error("An unexpected error occurred: ", ex);
        return new ErrorDTO(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public ErrorDTO handleUnsupportedRequestException(HttpRequestMethodNotSupportedException ex) {
        log.error("HTTP method not supported: {}", ex.getMessage(), ex);
        return new ErrorDTO(ErrorConstants.INVALID_REQUEST.getErrorCode(), ex.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorDTO handleNoResourceFoundException(NoResourceFoundException ex) {
        log.error("An unexpected error occurred: ", ex);
        return new ErrorDTO(ErrorConstants.INVALID_REQUEST.getErrorCode(), ex.getMessage());
    }

    @ExceptionHandler(WalletLockedException.class)
    @ResponseStatus(HttpStatus.LOCKED)
    public ErrorDTO handleWalletUnlockEligibilityException(WalletLockedException ex) {
        log.error("Wallet is not eligible to be unlocked due to the error: {}", ex.getMessage(), ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getErrorText());
    }

    @ExceptionHandler( value = InvalidInputException.class)
    public ResponseEntity<CredentialRequestResponseDTO> handleInvalidInput(InvalidInputException ex) {
        CredentialRequestResponseDTO credentialRequestResponseDTO = new CredentialRequestResponseDTO();
        ErrorDTO errors = new ErrorDTO(ex.getErrorCode(), ex.getMessage());
        credentialRequestResponseDTO.setVersion("1.0");
        credentialRequestResponseDTO.setErrors(Collections.singletonList(errors));
        return new ResponseEntity<>(credentialRequestResponseDTO, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataAccessResourceFailureException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorDTO handleDatabaseException(Exception ex) {
        log.error("Database error occurred:", ex);
        return new ErrorDTO(ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorCode(), ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorMessage());
    }

    @ExceptionHandler(ExternalServiceUnavailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorDTO handleExternalServiceUnavailable(ExternalServiceUnavailableException ex) {
        log.error("Connection to external service failed: ", ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getMessage());
    }

    @ExceptionHandler(UnauthorizedAccessException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorDTO handleUnAuthorizedAccess(UnauthorizedAccessException ex) {
        log.error("UnAuthorized access detected: ", ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getErrorText());
    }

    @ExceptionHandler(InvalidRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorDTO handleInvalidRequest(InvalidRequestException ex) {
        log.error("Invalid request parameters: ", ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getErrorText());
    }

    @ExceptionHandler(CredentialNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorDTO handleCredentialNotFoundException(CredentialNotFoundException ex) {
        log.error("Credential not found: ", ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getErrorText());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorDTO handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        log.error("Invalid request body: {}", ex.getMessage(), ex);
        String errorCode = ErrorConstants.INVALID_REQUEST.getErrorCode();
        String errorMessage;

        if (ex.getCause() instanceof com.fasterxml.jackson.core.JsonParseException) {
            errorMessage = "Invalid JSON format in request body";
        } else if (ex.getCause() instanceof com.fasterxml.jackson.databind.JsonMappingException) {
            errorMessage = "Request body does not match expected structure";
        } else if (ex.getMessage().contains("Required request body is missing")) {
            errorMessage = "Required request body is missing";
        } else if (ex.getMessage().contains("Content type")) {
            errorMessage = "Unsupported content type in request";
        } else {
            errorMessage = "Unable to process request body";
        }

        return new ErrorDTO(errorCode, errorMessage);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorDTO handleNoHandlerFoundException(NoHandlerFoundException ex) {
        log.error("No handler found for request: {} {}", ex.getHttpMethod(), ex.getRequestURL());
        return new ErrorDTO(ErrorConstants.RESOURCE_NOT_FOUND.getErrorCode(), ErrorConstants.RESOURCE_NOT_FOUND.getErrorMessage());
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorDTO handleHandlerMethodValidationException(HandlerMethodValidationException ex) {
        log.error("Validation error in handler method: {}", ex.getMessage());
        String errorMessage = ex.getAllValidationResults()
                .stream()
                .flatMap(r -> r.getResolvableErrors().stream())
                .map(MessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(", "));
        return new ErrorDTO(ErrorConstants.INVALID_REQUEST.getErrorCode(), errorMessage);
    }

    // Handler method to return 400 for validation failures
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDTO> handleValidationException(MethodArgumentNotValidException ex) {
        BindingResult br = ex.getBindingResult();
        String fieldErrors = br.getFieldErrors().stream()
                .map(fe -> fe.getField() + " " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        String globalErrors = br.getGlobalErrors().stream()
                .map(ObjectError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        String message = Stream.of(fieldErrors, globalErrors)
                .filter(s -> s != null && !s.isBlank())
                .collect(Collectors.joining("; "));
        if (message.isBlank()) {
            message = "Invalid request";
        }
        log.warn("Validation failed: {}", message);
        ErrorDTO err = new ErrorDTO("invalid_request", message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(err);
    }
}
