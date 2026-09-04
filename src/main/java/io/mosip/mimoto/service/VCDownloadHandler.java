package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;

public interface VCDownloadHandler {

    /**
     * Downloads the credential from the issuer.
     *
     * @param issuerDTO The issuerDTO
     * @param credentialConfigurationId The type of the credential
     * @param credentialIssuerWellKnownResponse The well-known response of the credential issuer
     * @param tokenResponse The token response containing the access token
     * @param walletId The ID of the wallet
     * @param base64Key The Base64-encoded wallet key
     * @param isLoginFlow Flag indicating if the flow is for login
     * @throws CredentialProcessingException If there is an error during credential processing
     * @throws InvalidCredentialResourceException If the credential resource is invalid
     * @throws ExternalServiceUnavailableException If an external service is unavailable
     */
    VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow, String dpopProof) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException;
}