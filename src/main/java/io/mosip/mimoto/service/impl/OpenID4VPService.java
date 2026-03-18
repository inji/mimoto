package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.WalletMetadata;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.constants.VPFormatType;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class OpenID4VPService {

    private final VerifierService verifierService;

    public OpenID4VPService(VerifierService verifierService) {
        this.verifierService = verifierService;
    }

    public OpenID4VP create(String presentationId) {
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setVpFormatsSupported(Map.of(VPFormatType.LDP_VC, new VPFormatSupported(List.of("EEd25519Signature2020"))));

        return new OpenID4VP(
                presentationId,
                walletMetadata
        );
    }

    /**
     * Extracts the presentation definition from the VerifiablePresentationSessionData object.
     *
     * @return The presentation definition if found, null otherwise.
     */
    public PresentationDefinition resolvePresentationDefinition(String presentationId, String authRequest, boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {
        if (presentationId == null || authRequest == null) {
            log.warn("Session data or OpenID4VP is null");
            return null;
        }
        OpenID4VP openID4VP = create(presentationId);
        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest()))
                .toList();

        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest, preRegisteredVerifiers, isVerifierClientPreregistered);
        return authorizationRequest.getPresentationDefinition();
    }

    /**
     * Reconstructs OpenID4VP from session data, authenticates the verifier and sends the OpenID4VP error to the verifier.
     *
     * @param sessionData session containing presentation id and original authorization request
     * @param payload     the error payload to forward
     * @return network response from verifier
     * @throws ApiNotAccessibleException when verifier list can't be fetched
     * @throws IOException               for underlying IO failures
     */
    public VerifierResponse sendErrorToVerifier(VerifiablePresentationSessionData sessionData, ErrorDTO payload) throws ApiNotAccessibleException, IOException, URISyntaxException {
        if (sessionData == null || sessionData.getPresentationId() == null || sessionData.getAuthorizationRequest() == null) {
            throw new IllegalArgumentException("Invalid presentation session data");
        }

        OpenID4VP openID4VP = create(sessionData.getPresentationId());

        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest()))
                .toList();

        // authenticateVerifier to populate internal state in OpenID4VP before sending error
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest(), preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());

        OpenID4VPExceptions.AccessDenied accessDeniedException = new OpenID4VPExceptions.AccessDenied(payload.getErrorMessage(), "OpenID4VPService");
        VerifierResponse verifierResponse = openID4VP.sendErrorInfoToVerifier(accessDeniedException);
        log.info("Sent rejection to verifier for presentationId {}. Response: {}", sessionData.getPresentationId(), verifierResponse);
        return verifierResponse;
    }
}