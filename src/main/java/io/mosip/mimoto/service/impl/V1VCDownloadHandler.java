package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.V1VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.V1Credential;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.DpopChallengeException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.V1CredentialRequestService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;

@Slf4j
@Component("v1")
public class V1VCDownloadHandler implements VCDownloadHandler {

    private static final String INVALID_NONCE = "invalid_nonce";
    private static final String DOWNLOAD_FAILURE_MESSAGE = "Unable to download credential from issuerId: %s, credentialConfigurationId: %s";
    private static final String EMPTY_CREDENTIAL_MESSAGE = "Credential response did not contain any credentials";
    private static final String REQUEST_BUILD_FAILURE_MESSAGE = "Unable to generate credential request";

    private final V1CredentialRequestService v1CredentialRequestService;
    private final RestApiClient restApiClient;

    public V1VCDownloadHandler(V1CredentialRequestService v1CredentialRequestService, RestApiClient restApiClient) {
        this.v1CredentialRequestService = v1CredentialRequestService;
        this.restApiClient = restApiClient;
    }

    @Override
    public VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow, String dpopProof) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException {

        V1VCCredentialRequest vcCredentialRequest = buildCredentialRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, walletId, base64Key, isLoginFlow);

        String credentialEndpoint = credentialIssuerWellKnownResponse.getCredentialEndPoint();
        String issuerId = issuerDTO.getIssuer_id();

        V1VCCredentialResponse response = postCredentialRequest(credentialEndpoint, vcCredentialRequest, tokenResponse, dpopProof);

        String nonceEndpoint = credentialIssuerWellKnownResponse.getNonceEndpoint();
        if (response != null && response.hasError() && INVALID_NONCE.equals(response.getError())
                && nonceEndpoint != null && !nonceEndpoint.isBlank()) {
            log.info("Received invalid_nonce error for issuerId: {}. Retrying with fresh nonce.", issuerId);
            vcCredentialRequest = buildCredentialRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, walletId, base64Key, isLoginFlow);
            response = postCredentialRequest(credentialEndpoint, vcCredentialRequest, tokenResponse, dpopProof);
        }

        if (response == null || response.hasError()) {
            String errorDetail = response != null ? response.getError() + ": " + response.getErrorDescription() : "no response";
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(),
                    String.format(DOWNLOAD_FAILURE_MESSAGE, issuerId, credentialConfigurationId) + " - " + errorDetail);
        }

        List<V1Credential> credentials = response.getCredentials();
        if (credentials == null || credentials.isEmpty()) {
            throw new InvalidCredentialResourceException(EMPTY_CREDENTIAL_MESSAGE);
        }

        String format = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialConfigurationId).getFormat();

        log.debug("V1 VC Credential Response received for issuerId: {}", issuerId);
        return VCCredentialResponse.builder()
                .format(format)
                .credential(credentials.getFirst().getCredential())
                .build();
    }

    private V1VCCredentialRequest buildCredentialRequest(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse wellKnownResponse, String walletId, String base64Key, boolean isLoginFlow) throws CredentialProcessingException {
        try {
            return v1CredentialRequestService.buildRequest(issuerDTO, credentialConfigurationId, wellKnownResponse, walletId, base64Key, isLoginFlow);
        } catch (Exception e) {
            log.error("Failed to generate V1 VC credential request for issuerId: {}", issuerDTO.getIssuer_id(), e);
            throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), REQUEST_BUILD_FAILURE_MESSAGE, e);
        }
    }

    private V1VCCredentialResponse postCredentialRequest(String credentialEndpoint, V1VCCredentialRequest request,
                                                         TokenResponseDTO tokenResponse, String dpopProof) {
        try {
            return restApiClient.postCredentialApi(credentialEndpoint, MediaType.APPLICATION_JSON, request,
                    V1VCCredentialResponse.class, tokenResponse.getAccess_token(), tokenResponse.getToken_type(), dpopProof);
        } catch (DpopChallengeException e) {
            throw e;
        }
    }
}
