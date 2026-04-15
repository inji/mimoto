package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.Draft13CredentialRequestService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;

@Slf4j
@Component("draft-13")
public class Draft13VCDownloadHandler implements VCDownloadHandler {
    private final Draft13CredentialRequestService draft13CredentialRequestService;
    private final RestApiClient restApiClient;

    public Draft13VCDownloadHandler(Draft13CredentialRequestService draft13CredentialRequestService, RestApiClient restApiClient) {
        this.draft13CredentialRequestService = draft13CredentialRequestService;
        this.restApiClient = restApiClient;
    }

    @Override
    public VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException {
        Draft13VCCredentialRequest vcCredentialRequest;
        try {
            vcCredentialRequest = draft13CredentialRequestService.buildRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, tokenResponse.getC_nonce(), walletId, base64Key, isLoginFlow);
        } catch (Exception e) {
            log.error("Failed to generate VC credential request for issuerId: {}", issuerDTO.getIssuer_id(), e);
            throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Unable to generate credential request", e);
        }

        return fetchCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, tokenResponse.getAccess_token(), issuerDTO.getIssuer_id(), credentialConfigurationId);
    }

    private VCCredentialResponse fetchCredential(String credentialEndpoint, Draft13VCCredentialRequest vcCredentialRequest, String accessToken, String issuerId, String credentialConfigId) throws InvalidCredentialResourceException, ExternalServiceUnavailableException {
        VerifiableCredentialResponse response;

        try {
            response = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                    vcCredentialRequest, VerifiableCredentialResponse.class, accessToken);
        } catch (Exception e) {
            String message = String.format("Unable to download credential from issuerId: %s, credentialConfigurationId: %s", issuerId, credentialConfigId);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), message, e);
        }

        if (response == null) {
            String message = String.format("Unable to download credential from issuerId: %s, credentialConfigurationId: %s", issuerId, credentialConfigId);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), message);
        }

        if (response.getCredential() == null) {
            throw new InvalidCredentialResourceException("Credential response did not contain a credential");
        }

        log.debug("VC Credential Response received");
        return new VCCredentialResponse(vcCredentialRequest.getFormat(), response.getCredential());
    }
}