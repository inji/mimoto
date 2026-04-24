package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;

public interface CredentialRequestService {
    VCCredentialRequest buildRequest(
            IssuerV2DTO issuerDTO,
            String credentialConfigurationId,
            CredentialIssuerWellKnownResponse wellKnownResponse,
            String cNonce,
            String walletId,
            String base64EncodedWalletKey,
            boolean isLoginFlow
    ) throws Exception;
}