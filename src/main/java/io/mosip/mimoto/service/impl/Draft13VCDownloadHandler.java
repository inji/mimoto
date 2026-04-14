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
import io.mosip.mimoto.service.CredentialRequestService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;

@Slf4j
@Component("draft13")
public class Draft13VCDownloadHandler implements VCDownloadHandler {
    private final CredentialRequestService credentialRequestService;
    private final RestApiClient restApiClient;

    public Draft13VCDownloadHandler(CredentialRequestService credentialRequestService, RestApiClient restApiClient) {
        this.credentialRequestService = credentialRequestService;
        this.restApiClient = restApiClient;
    }

    @Override
    public VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException {
        Draft13VCCredentialRequest vcCredentialRequest;
        try {
            vcCredentialRequest = credentialRequestService.buildRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, tokenResponse.getC_nonce(), walletId, base64Key, isLoginFlow);
        } catch (Exception e) {
            log.error("Failed to generate VC credential request for issuerId: {}", issuerDTO.getIssuer_id(), e);
            throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Unable to generate credential request", e);
        }

        return fetchCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, tokenResponse.getAccess_token(), issuerDTO.getIssuer_id(), credentialConfigurationId);
    }

    /**
     * Downloads credential from the issuer endpoint.
     *
     * @param credentialEndpoint The credential endpoint
     * @param vcCredentialRequest The credential request
     * @param accessToken The access token
     * @param issuerId The ID of the issuer
     * @param credentialConfigId The credential configuration ID
     * @return VCCredentialResponse containing the credential
     * @throws InvalidCredentialResourceException If the credential resource is invalid
     * @throws ExternalServiceUnavailableException If an external service is unavailable
     */
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
            throw new InvalidCredentialResourceException("VC Credential Issue API not accessible");
        }

        log.debug("VC Credential Response received");
        return new VCCredentialResponse(vcCredentialRequest.getFormat(), response.getCredential());
    }
}