package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Map;

public interface IdpService {
    HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, String issuerId, String tokenEndpoint) throws IOException, IssuerOnboardingException, ApiNotAccessibleException, InvalidIssuerIdException;

    String getTokenEndpoint(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException;

    TokenResponseDTO getTokenResponse(Map<String, String> params) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException;

    TokenResponseDTO getTokenResponse(VerifiableCredentialRequestDTO verifiableCredentialRequest) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException;

    ResponseEntity<String> getTokenResponseV2(Map<String, String> params, String dpopProof) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException, IssuerOnboardingException;
}
