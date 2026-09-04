package io.mosip.mimoto.service;

import com.google.zxing.WriterException;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.exception.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface CredentialService {

    /**
     * Downloads credential as PDF.
     *
     * @param issuerId           The issuer ID
     * @param credentialType     The credential type
     * @param response           The token response
     * @param credentialValidity The credential validity
     * @param locale             The locale
     * @param dpopProof          Optional DPoP proof from the client
     * @return ByteArrayInputStream containing the PDF
     * @throws ApiNotAccessibleException        If the issuer API is not accessible
     * @throws IOException                      If an I/O error occurs
     * @throws InvalidWellknownResponseException If the well-known response is invalid
     * @throws ExternalServiceUnavailableException If the credential download service is unavailable
     * @throws WriterException                  If QR code generation fails
     */
    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale, String dpopProof)
            throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException, ExternalServiceUnavailableException, WriterException;

    /**
     * Downloads credential and stores it in the database.
     *
     * @param tokenResponse             The token response containing the access token
     * @param credentialConfigurationId The type of the credential
     * @param walletId                  The ID of the wallet
     * @param base64Key                 The Base64-encoded wallet key
     * @param issuerId                  The ID of the issuer
     * @param locale                    The locale for the response
     * @return The stored VerifiableCredential response
     * @throws InvalidRequestException             If input parameters are invalid
     * @throws CredentialProcessingException       If processing fails
     * @throws ExternalServiceUnavailableException If an external service is unavailable
     * @throws VCVerificationException             If credential verification fails
     * @throws InvalidCredentialResourceException  If the credential resource is invalid
     */
    VerifiableCredentialResponseDTO downloadCredentialAndStoreInDB(
            TokenResponseDTO tokenResponse, String credentialConfigurationId, String walletId,
            String base64Key, String issuerId, String locale, String dpopProof)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException, VCVerificationException, InvalidCredentialResourceException;
}