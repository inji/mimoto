package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.VPResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;

import java.io.IOException;
import java.net.URISyntaxException;

import org.springframework.http.ResponseEntity;

public interface PresentationService {

    String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException;
    VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, OpenID4VPExceptions, URISyntaxException;
    SubmitPresentationResponseDTO rejectVerifier(String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload) throws VPErrorNotSentException;
    ResponseEntity<?> handlePresentationAction(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData vpSessionData, String base64Key);
}
