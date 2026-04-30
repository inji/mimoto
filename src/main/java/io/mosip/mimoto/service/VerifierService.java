package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.authorizationRequest.Verifier;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

public interface VerifierService {
    Optional<VerifierDTO> getVerifierByClientId(String clientId) throws ApiNotAccessibleException, IOException;
    void validateVerifier(String clientId, String responseUri, String redirectUri) throws ApiNotAccessibleException, JsonProcessingException;
    VerifiersDTO getTrustedVerifiers() throws ApiNotAccessibleException, IOException;
    boolean isVerifierTrustedByWallet(String verifierId, String walletId);
    boolean isVerifierClientPreregistered(List<Verifier> preRegisteredVerifiers, String urlEncodedVPAuthorizationRequest) throws URISyntaxException;
}
