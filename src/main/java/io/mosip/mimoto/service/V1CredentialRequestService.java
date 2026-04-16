package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.SigningKeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class V1CredentialRequestService {

    private static final SigningAlgorithm FALLBACK_SIGNING_ALG = SigningAlgorithm.ED25519;
    private static final String PROOF_TYPE_JWT = "jwt";
    private final RestApiClient restApiClient;
    private final KeyPairRetrievalService keyPairService;
    @Value("${signing.algorithms.priority.order:ED25519,ES256K,ES256,RS256}")
    private String signingAlgorithmsPriorityOrder;

    public V1CredentialRequestService(RestApiClient restApiClient, KeyPairRetrievalService keyPairService) {
        this.restApiClient = restApiClient;
        this.keyPairService = keyPairService;
    }

    public V1VCCredentialRequest buildRequest(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse wellKnownResponse, String walletId, String base64EncodedWalletKey, boolean isLoginFlow) throws Exception {

        CredentialsSupportedResponse credentialsSupportedResponse = wellKnownResponse.getCredentialConfigurationsSupported().get(credentialConfigurationId);

        SigningAlgorithm signingAlgorithm = resolveAlgorithm(credentialsSupportedResponse);

        String cNonce = fetchNonce(wellKnownResponse.getNonceEndpoint());

        String jwt;
        KeyPair keyPair;
        if (isLoginFlow) {
            keyPair = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, signingAlgorithm);
        } else {
            keyPair = SigningKeyUtil.generateKeyPair(signingAlgorithm);
            log.debug("Generated KeyPair for signing algorithm: {}", signingAlgorithm);
        }
        jwt = SigningKeyUtil.generateJwt(signingAlgorithm, wellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), cNonce, keyPair);

        Map<String, List<String>> proofs = Map.of(PROOF_TYPE_JWT, List.of(jwt));

        return V1VCCredentialRequest.builder().credentialConfigurationId(credentialConfigurationId).proofs(proofs).build();
    }

    private String fetchNonce(String nonceEndpoint) throws Exception {
        if (nonceEndpoint == null || nonceEndpoint.isBlank()) {
            log.debug("No nonce_endpoint configured, building request without nonce");
            return null;
        }

        log.debug("Fetching nonce from endpoint: {}", nonceEndpoint);
        NonceResponse nonceResponse = restApiClient.postApi(nonceEndpoint, MediaType.APPLICATION_JSON, null, NonceResponse.class);

        if (nonceResponse == null || nonceResponse.getCNonce() == null) {
            log.warn("Nonce endpoint returned null or empty response");
            return null;
        }

        return nonceResponse.getCNonce();
    }

    public Set<String> getSigningAlgorithmsPriorityOrder() {
        return Arrays.stream(signingAlgorithmsPriorityOrder.split(",")).map(String::trim).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private SigningAlgorithm resolveAlgorithm(CredentialsSupportedResponse credentialsSupportedResponse) {
        Map<String, ProofTypesSupported> proofTypesSupported = credentialsSupportedResponse.getProofTypesSupported();
        ProofTypesSupported proofSigningAlgValuesSupported = proofTypesSupported.get(PROOF_TYPE_JWT);
        Set<String> signingAlgoPriorityOrderSet = getSigningAlgorithmsPriorityOrder();

        return Optional.ofNullable(proofSigningAlgValuesSupported).map(ProofTypesSupported::getProofSigningAlgValuesSupported).flatMap(issuerSupportedAlgorithms -> signingAlgoPriorityOrderSet.stream().filter(priorityAlgorithm -> issuerSupportedAlgorithms.stream().anyMatch(issuerSupportedAlgorithm -> issuerSupportedAlgorithm.equalsIgnoreCase(priorityAlgorithm))).findFirst()).map(SigningAlgorithm::fromString).orElseGet(() -> {
            if (proofSigningAlgValuesSupported == null) {
                log.warn("JWT proof type is missing in proof_types_supported field of Issuer well-known so falling back to {}", FALLBACK_SIGNING_ALG);
            } else {
                log.warn("None of the Issuer Supported Algorithms: {} are found in the predefined signing algorithms priority order: {} so falling back to {}", proofSigningAlgValuesSupported.getProofSigningAlgValuesSupported(), signingAlgoPriorityOrderSet, FALLBACK_SIGNING_ALG);
            }
            return FALLBACK_SIGNING_ALG;
        });
    }
}
