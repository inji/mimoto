package io.mosip.mimoto.service;

import com.google.zxing.WriterException;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import jakarta.servlet.http.HttpSession;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface CredentialService {

    /**
     * Exchanges the authorization code, builds DPoP proofs, and downloads the credential as PDF.
     *
     * @param issuerId           The issuer ID
     * @param credentialType     The credential type
     * @param credentialValidity The credential validity
     * @param locale             The locale
     * @param code               The authorization code
     * @param state              OAuth state identifying the DPoP session
     * @param httpSession        The HTTP session that holds the DPoP session
     * @return ByteArrayInputStream containing the PDF
     */
    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, String credentialValidity,
                                                 String locale, String code, String state, HttpSession httpSession)
            throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException,
            ExternalServiceUnavailableException, WriterException, AuthorizationServerWellknownResponseException,
            IssuerOnboardingException;

    /**
     * Exchanges the authorization code, builds DPoP proofs, downloads the credential, and stores it.
     *
     * @param issuerId                  The ID of the issuer
     * @param credentialConfigurationId The type of the credential
     * @param walletId                  The ID of the wallet
     * @param base64Key                 The Base64-encoded wallet key
     * @param locale                    The locale for the response
     * @param code                      The authorization code
     * @param state                     OAuth state identifying the DPoP session
     * @param httpSession               The HTTP session that holds the DPoP session
     * @return The stored VerifiableCredential response
     */
    VerifiableCredentialResponseDTO downloadCredentialAndStoreInDB(
            String issuerId, String credentialConfigurationId, String walletId, String base64Key,
            String locale, String code, String state, HttpSession httpSession)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException,
            VCVerificationException, InvalidCredentialResourceException, ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException, InvalidWellknownResponseException, IssuerOnboardingException;
}