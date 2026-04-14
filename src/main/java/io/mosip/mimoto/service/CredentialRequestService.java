package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;

public interface CredentialRequestService {
    Draft13VCCredentialRequest buildRequest(
            IssuerDTO issuerDTO,
            String credentialConfigurationId,
            CredentialIssuerWellKnownResponse wellKnownResponse,
            String cNonce,
            String walletId,
            String base64EncodedWalletKey,
            boolean isLoginFlow
    ) throws Exception;
}