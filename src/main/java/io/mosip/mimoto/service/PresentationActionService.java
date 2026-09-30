package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import org.springframework.http.ResponseEntity;

/**
 * Service interface for handling presentation actions (submission or rejection)
 */
public interface PresentationActionService {

    /**
     * Handles presentation action - either submission with credentials or rejection with error
     * <p>
     * This method handles all business logic and exceptions internally, returning appropriate
     * HTTP responses. The controller should only catch generic exceptions for unexpected errors.
     *
     * @param walletId The wallet ID
     * @param presentationId The presentation ID
     * @param request The request containing either selected credentials or error details
     * @param vpSessionData The session data containing presentation information
     * @param base64Key The wallet key for decryption (required for submission)
     * @return ResponseEntity with appropriate response type and HTTP status
     */
    ResponseEntity<Object> handlePresentationAction(
            String walletId,
            String presentationId,
            SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData vpSessionData,
            String base64Key
    );
}

