package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.V1VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.V1VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
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
@Component(VCSpecificationVersion.V1_VERSION)
public class V1VCDownloadHandler implements VCDownloadHandler {

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
    public VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException {

        V1VCCredentialRequest vcCredentialRequest = buildCredentialRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, walletId, base64Key, isLoginFlow);

        String credentialEndpoint = credentialIssuerWellKnownResponse.getCredentialEndPoint();
        String accessToken = tokenResponse.getAccess_token();
        String issuerId = issuerDTO.getIssuer_id();

        V1VCCredentialResponse response = postCredentialRequest(credentialEndpoint, vcCredentialRequest, accessToken);

        String nonceEndpoint = credentialIssuerWellKnownResponse.getNonceEndpoint();
        if (response == null && nonceEndpoint != null && !nonceEndpoint.isBlank()) {
            log.info("Credential request failed for issuerId: {}. Retrying with fresh nonce.", issuerId);
            vcCredentialRequest = buildCredentialRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, walletId, base64Key, isLoginFlow);
            response = postCredentialRequest(credentialEndpoint, vcCredentialRequest, accessToken);
        }

        if (response == null) {
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), String.format(DOWNLOAD_FAILURE_MESSAGE, issuerId, credentialConfigurationId));
        }

        List<Object> credentials = response.getCredentials();
        if (credentials == null || credentials.isEmpty()) {
            throw new InvalidCredentialResourceException(EMPTY_CREDENTIAL_MESSAGE);
        }

        String format = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialConfigurationId).getFormat();

        log.debug("V1 VC Credential Response received for issuerId: {}", issuerId);
        return new VCCredentialResponse(format, credentials.getFirst());
    }

    private V1VCCredentialRequest buildCredentialRequest(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse wellKnownResponse, String walletId, String base64Key, boolean isLoginFlow) throws CredentialProcessingException {
        try {
            return v1CredentialRequestService.buildRequest(issuerDTO, credentialConfigurationId, wellKnownResponse, walletId, base64Key, isLoginFlow);
        } catch (Exception e) {
            log.error("Failed to generate V1 VC credential request for issuerId: {}", issuerDTO.getIssuer_id(), e);
            throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), REQUEST_BUILD_FAILURE_MESSAGE, e);
        }
    }

    private V1VCCredentialResponse postCredentialRequest(String credentialEndpoint, V1VCCredentialRequest request, String accessToken) {
        try {
            return restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON, request, V1VCCredentialResponse.class, accessToken);
        } catch (Exception e) {
            log.error("Error posting V1 credential request to {}", credentialEndpoint, e);
            return null;
        }
    }
}
