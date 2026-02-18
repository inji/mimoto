package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerResponseDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.IssuerConfigUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import java.lang.NullPointerException;


@Service
@Slf4j
@Validated
public class IssuersServiceImpl implements IssuersService {

    private static final String WELL_KNOWN_CREDENTIAL_ISSUER_PATH = "/.well-known/openid-credential-issuer";
    private static final String DEFAULT_OAUTH_REDIRECT_URI = "io.mosip.residentapp.inji://oauthredirect";

    @Autowired
    private Utilities utilities;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IssuerConfigUtil issuersConfigUtil;

    @Override
    @Cacheable(value = "issuersConfig", key = "#p0 ?: 'allIssuersConfig'")
    public IssuersDTO getIssuers(String search) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO = getAllIssuers();
        issuersDTO = getAllEnabledIssuers(issuersDTO);
        issuersDTO = getFilteredIssuers(issuersDTO, search);

        return issuersDTO;
    }

    @Override
    public IssuerDTO getIssuerDetails(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO = getAllIssuers();
        issuersDTO = getAllEnabledIssuers(issuersDTO);

        return issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getIssuer_id().equals(issuerId))
                .findFirst()
                .orElseThrow(InvalidIssuerIdException::new);
    }

    private IssuersDTO getAllEnabledIssuers(IssuersDTO issuersDTO) {
        return new IssuersDTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> "true".equals(issuer.getEnabled()))
                .collect(Collectors.toList()));
    }

    private IssuersDTO getFilteredIssuers(IssuersDTO issuersDTO, String search) {
        if (StringUtils.isEmpty(search)) {
            return issuersDTO;
        }

        return new IssuersDTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getDisplay().stream()
                        .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains(search.toLowerCase())))
                .collect(Collectors.toList()));
    }

    @Override
    public IssuersDTO getAllIssuers() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }

        issuersDTO = objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class);

        return issuersDTO;
    }

    @Override
    public CredentialIssuerConfiguration getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuersConfigUtil.getIssuerWellknown(getIssuerDetails(issuerId).getCredential_issuer_host());
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = issuersConfigUtil.getAuthServerWellknown(credentialIssuerWellKnownResponse.getAuthorizationServers().get(0));

        return new CredentialIssuerConfiguration(
                credentialIssuerWellKnownResponse.getCredentialIssuer(),
                credentialIssuerWellKnownResponse.getAuthorizationServers(),
                credentialIssuerWellKnownResponse.getCredentialEndPoint(),
                credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported(),
                authorizationServerWellKnownResponse
        );
    }

    @Override
    public IssuerConfig getIssuerConfig(String issuerId, @NotBlank String credentialType) throws ApiNotAccessibleException, InvalidIssuerIdException {
        log.info("Fetching issuer config for issuerId: {}", issuerId);
        try {
            IssuerDTO issuerDTO = getIssuerDetails(issuerId);
            CredentialIssuerWellKnownResponse wellKnownResponse = issuersConfigUtil.getIssuerWellknown(issuerDTO.getCredential_issuer_host());
            return new IssuerConfig(
                    issuerDTO,
                    wellKnownResponse,
                    wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType)
            );
        } catch (Exception e) {
            log.error("Failed to fetch issuer config for issuerId: {}", issuerId, e);
            if (e instanceof InvalidIssuerIdException) {
                throw (InvalidIssuerIdException) e;
            }
            throw new ApiNotAccessibleException("Unable to fetch issuer configuration for issuerId: " + issuerId, e);
        }
    }

    @Override
    public List<IssuerResponseDTO> getIssuersResponse(String search) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO = getIssuers(search);
        return issuersDTO.getIssuers().parallelStream().map(this::toIssuerResponseDTO).collect(Collectors.toList());
    }

    @Override
    public IssuerResponseDTO getIssuerResponseDetails(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = getIssuerDetails(issuerId);
        return toIssuerResponseDTO(issuerDTO);
    }

    /**
     * Maps an {@link IssuerDTO} (from config) to {@link IssuerResponseDTO} (API response).
     */
    private IssuerResponseDTO toIssuerResponseDTO(IssuerDTO issuer) {
        String credentialIssuerHost = issuer.getCredential_issuer_host();
        String wellKnownEndpointUrl = credentialIssuerHost + WELL_KNOWN_CREDENTIAL_ISSUER_PATH;

        String credentialEndpointUrl = null;
        try {
            CredentialIssuerWellKnownResponse wellKnownResponse = issuersConfigUtil.getIssuerWellknown(credentialIssuerHost);
            credentialEndpointUrl = wellKnownResponse.getCredentialEndPoint();
        } catch (ApiNotAccessibleException | IOException | InvalidWellknownResponseException | NullPointerException e) {
            log.warn("Could not fetch well-known for issuer {} ({}): using fallbacks", issuer.getIssuer_id(), e.getMessage());
        }

        IssuerResponseDTO issuerResponse = new IssuerResponseDTO();
        issuerResponse.setIssuerId(issuer.getIssuer_id());
        issuerResponse.setProtocol(issuer.getProtocol());
        issuerResponse.setDisplay(issuer.getDisplay());
        issuerResponse.setClientId(issuer.getClient_id());
        issuerResponse.setWellknownEndpoint(wellKnownEndpointUrl);
        issuerResponse.setRedirectUri(DEFAULT_OAUTH_REDIRECT_URI);
        issuerResponse.setTokenEndpoint(issuer.getToken_endpoint());
        issuerResponse.setClientAlias(issuer.getClient_alias());
        issuerResponse.setQrCodeType(issuer.getQr_code_type());
        issuerResponse.setEnabled(issuer.getEnabled());
        issuerResponse.setCredentialIssuer(issuer.getIssuer_id());
        issuerResponse.setCredentialIssuerHost(credentialIssuerHost);
        issuerResponse.setAuthorizationAudience(credentialEndpointUrl);
        issuerResponse.setProxyTokenEndpoint(credentialEndpointUrl);
        return issuerResponse;
    }
}