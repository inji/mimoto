package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.SdJwtVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.WalletConfig;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.constants.ClientIdPrefix;
import io.mosip.openID4VP.constants.ProofType;
import io.mosip.openID4VP.constants.RequestUriMethod;
import io.mosip.openID4VP.constants.ResponseType;
import io.mosip.openID4VP.constants.VPFormatType;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
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
        return create(presentationId, List.of(), true);
    }

    public OpenID4VP create(String presentationId, List<Verifier> trustedVerifiers) {
        return create(presentationId, trustedVerifiers, true);
    }

    public OpenID4VP create(String presentationId, List<Verifier> trustedVerifiers, boolean validatePreRegisteredVerifier) {
        Map<VPFormatType, VPFormatSupported> vpFormatsSupported = Map.of(
                VPFormatType.LDP_VC, new LdpVpFormatSupported(List.of(ProofType.Ed25519Signature2020), null),
                VPFormatType.VC_SD_JWT, new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA")),
                VPFormatType.DC_SD_JWT, new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA"))
        );

        WalletConfig walletConfig = new WalletConfig(
                vpFormatsSupported,
                List.of(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.REDIRECT_URI),
                null, null, null,
                List.of(ResponseType.VP_TOKEN),
                true,
                List.of(RequestUriMethod.GET, RequestUriMethod.POST),
                trustedVerifiers,
                validatePreRegisteredVerifier
        );

        return new OpenID4VP(presentationId, walletConfig);
    }

    public PresentationDefinition resolvePresentationDefinition(
            String presentationId, String authRequest, boolean isVerifierClientPreregistered)
            throws ApiNotAccessibleException, IOException {

        if (presentationId == null || authRequest == null) {
            return null;
        }

        OpenID4VP openID4VP = create(presentationId, getPreRegisteredVerifiers(), isVerifierClientPreregistered);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest);

        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest peRequest) {
            return peRequest.getPresentationDefinition();
        }
        return null;
    }

    public DCQLQuery resolveDcqlQuery(
            String presentationId, String authRequest, boolean isVerifierClientPreregistered)
            throws ApiNotAccessibleException, IOException {

        if (presentationId == null || authRequest == null) {
            return null;
        }

        OpenID4VP openID4VP = create(presentationId, getPreRegisteredVerifiers(), isVerifierClientPreregistered);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest);

        if (authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest) {
            return dcqlRequest.getDcqlQuery();
        }
        return null;
    }

    public VerifierResponse sendErrorToVerifier(
            VerifiablePresentationSessionData sessionData, ErrorDTO payload)
            throws ApiNotAccessibleException, IOException, URISyntaxException {

        if (sessionData == null || sessionData.getPresentationId() == null
                || sessionData.getAuthorizationRequest() == null) {
            throw new IllegalArgumentException("Invalid presentation session data");
        }

        OpenID4VP openID4VP = create(
                sessionData.getPresentationId(),
                getPreRegisteredVerifiers(),
                sessionData.isVerifierClientPreregistered());

        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

        Exception errorForVerifier = toOpenID4VPException(payload);
        VerifierResponse verifierResponse = openID4VP.sendErrorInfoToVerifier(errorForVerifier);
        log.info("Sent error to verifier for presentationId={}. Response: {}",
                sessionData.getPresentationId(), verifierResponse);
        return verifierResponse;
    }

    public List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(v -> new Verifier(v.getClientId(), v.getResponseUris(), v.getJwksUri(), v.getAllowUnsignedRequest()))
                .toList();
    }

    private Exception toOpenID4VPException(ErrorDTO payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Error payload must not be null");
        }
        String message = payload.getErrorMessage() != null ? payload.getErrorMessage() : "";
        String code = payload.getErrorCode();

        if (OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA.equals(code)) {
            return new OpenID4VPExceptions.InvalidTransactionData(message, "OpenID4VPService");
        }
        return new OpenID4VPExceptions.AccessDenied(message, "OpenID4VPService");
    }
}
