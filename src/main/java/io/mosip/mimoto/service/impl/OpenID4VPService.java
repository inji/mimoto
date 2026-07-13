package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.mimoto.util.AuthorizationRequestHelper;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.SdJwtVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.WalletConfig;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.constants.ProofType;
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

import static io.mosip.openID4VP.authorizationRequest.WalletConfigDefaultsKt.getDefaultClientIdPrefixesSupported;
import static io.mosip.openID4VP.authorizationRequest.WalletConfigDefaultsKt.getDefaultEncryptionAlgorithmSupported;
import static io.mosip.openID4VP.authorizationRequest.WalletConfigDefaultsKt.getDefaultEncryptionMethodSupported;
import static io.mosip.openID4VP.authorizationRequest.WalletConfigDefaultsKt.getDefaultResponseTypeSupported;
import static io.mosip.openID4VP.authorizationRequest.WalletConfigDefaultsKt.getDefaultSignatureAlgorithmSupported;

@Component
@Slf4j
public class OpenID4VPService {

    private final VerifierService verifierService;

    public OpenID4VPService(VerifierService verifierService) {
        this.verifierService = verifierService;
    }

    public OpenID4VP create(String presentationId, List<Verifier> trustedVerifiers, boolean validateTrustedVerifier) {
        return new OpenID4VP(presentationId, buildWalletConfig(trustedVerifiers, validateTrustedVerifier));
    }

    private WalletConfig buildWalletConfig(List<Verifier> trustedVerifiers, boolean validateTrustedVerifier) {
        Map<VPFormatType, VPFormatSupported> vpFormatsSupported = Map.of(
                VPFormatType.LDP_VC, new LdpVpFormatSupported(List.of(ProofType.Ed25519Signature2020), null),
                VPFormatType.VC_SD_JWT, new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA")),
                VPFormatType.DC_SD_JWT, new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA"))
        );

        WalletConfig libraryDefaults = new WalletConfig();
        return new WalletConfig(
                vpFormatsSupported,
                getDefaultClientIdPrefixesSupported(),
                getDefaultSignatureAlgorithmSupported(),
                getDefaultEncryptionAlgorithmSupported(),
                getDefaultEncryptionMethodSupported(),
                getDefaultResponseTypeSupported(),
                libraryDefaults.isPresentationDefinitionUriSupported(),
                trustedVerifiers != null ? trustedVerifiers : List.of(),
                validateTrustedVerifier
        );
    }

    /**
     * Authenticates the verifier authorization request and returns the presentation definition
     * for Draft-23 (Presentation Exchange) requests. Returns {@code null} for DCQL requests
     * or when {@code presentationId} or {@code authRequest} are missing.
     *
     * @param presentationId                 presentation session identifier from session data
     * @param authRequest                    raw authorization request from session data
     * @param isVerifierClientPreregistered  whether the verifier client is pre-registered
     * @return the presentation definition for Presentation Exchange requests, otherwise {@code null}
     */
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

    /**
     * Authenticates the verifier authorization request and returns the DCQL query
     * for OVP 1.0 (DCQL) requests. Returns {@code null} for Presentation Exchange requests
     * or when {@code presentationId} or {@code authRequest} are missing.
     *
     * @param presentationId                 presentation session identifier from session data
     * @param authRequest                    raw authorization request from session data
     * @param isVerifierClientPreregistered  whether the verifier client is pre-registered
     * @return the DCQL query for DCQL authorization requests, otherwise {@code null}
     */
    public DCQLQuery resolveDcqlQuery(
            String presentationId, String authRequest, boolean isVerifierClientPreregistered)
            throws ApiNotAccessibleException, IOException {

        if (presentationId == null || authRequest == null) {
            return null;
        }

        OpenID4VP openID4VP = create(presentationId, getPreRegisteredVerifiers(), isVerifierClientPreregistered);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest);
        return AuthorizationRequestHelper.extractDcqlQuery(authorizationRequest);
    }

    /**
     * Reconstructs OpenID4VP from session data, authenticates the verifier, and sends the OpenID4VP error to the verifier.
     *
     * @param sessionData session containing presentation id and original authorization request
     * @param payload     the error payload to forward
     * @return network response from verifier
     * @throws ApiNotAccessibleException when verifier list can't be fetched
     * @throws IOException               for underlying IO failures
     * @throws URISyntaxException        when the verifier response URI is invalid
     */
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

        // authenticateVerifier to populate internal state in OpenID4VP before sending error
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

        Exception errorForVerifier = openId4VPErrorException(payload);
        VerifierResponse verifierResponse = openID4VP.sendErrorInfoToVerifier(errorForVerifier);
        log.info("Sent error to verifier for presentationId={}. Response: {}",
                sessionData.getPresentationId(), verifierResponse);
        return verifierResponse;
    }

    public List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(v -> new Verifier(v.getClientId(), v.getResponseUris(), v.getJwksUri(), v.getAllowUnsignedRequest(), v.getSpecVersion()))
                .toList();
    }

    /**
     * Maps wallet {@link ErrorDTO#errorCode} to inji-openid4vp exceptions {@code error}
     * matches (e.g. {@link OpenID4VPErrorCodes#INVALID_TRANSACTION_DATA} vs {@link OpenID4VPErrorCodes#ACCESS_DENIED}).
     */
    private Exception openId4VPErrorException(ErrorDTO payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Error payload must not be null");
        }
        String message = payload.getErrorMessage() != null ? payload.getErrorMessage() : "";
        String code = payload.getErrorCode();

        if (OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA.equals(code)) {
            return new OpenID4VPExceptions.InvalidTransactionData(message, "OpenID4VPService");
        }
        // Default to AccessDenied for any unrecognized error codes
        return new OpenID4VPExceptions.AccessDenied(message, "OpenID4VPService");
    }
}
