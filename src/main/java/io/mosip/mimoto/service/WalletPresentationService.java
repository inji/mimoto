package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.VPResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.net.URISyntaxException;

/**
 * Service interface for handling wallet presentation operations
 */
public interface WalletPresentationService {
    VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, OpenID4VPExceptions, URISyntaxException;
    ResponseEntity<?> handlePresentationAction(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData vpSessionData, String base64Key);
    MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException;
}

