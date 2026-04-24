package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.IssuersV2DTO;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.IssuerConfigUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@Service
@Slf4j
@Validated
public class IssuersServiceImpl implements IssuersService {

    private final Utilities utilities;

    private final ObjectMapper objectMapper;

    private final IssuerConfigUtil issuersConfigUtil;

    public IssuersServiceImpl(Utilities utilities, ObjectMapper objectMapper, IssuerConfigUtil issuersConfigUtil) {
        this.utilities = utilities;
        this.objectMapper = objectMapper;
        this.issuersConfigUtil = issuersConfigUtil;
    }

    @Override
    @Cacheable(value = "issuersConfig", key = "#p0 ?: 'allIssuersConfig'")
    public IssuersDTO getIssuers(String search) throws ApiNotAccessibleException, IOException {
        IssuersV2DTO issuersDTO = getAllEnabledIssuers();
        issuersDTO = getFilteredIssuers(issuersDTO, search);

        return new IssuersDTO(
                issuersDTO.getIssuers().stream()
                .map(issuer -> {
                    try {
                        return toIssuerDTO(issuer);
                    } catch (AuthorizationServerWellknownResponseException | ApiNotAccessibleException | IOException |
                             InvalidWellknownResponseException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList())
        );

    }

    @Override
    public IssuerDTO getIssuerDetails(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuersV2DTO issuersDTO = getAllEnabledIssuers();

        IssuerV2DTO issuerV2DTO = issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getIssuerId().equals(issuerId))
                .findFirst()
                .orElseThrow(InvalidIssuerIdException::new);
        try {
            return toIssuerDTO(issuerV2DTO);
        } catch (AuthorizationServerWellknownResponseException | InvalidWellknownResponseException e) {
            throw new RuntimeException(e);
        }
    }

    private IssuersV2DTO getAllEnabledIssuers() throws ApiNotAccessibleException, IOException {
        IssuersV2DTO issuersDTO = getAllIssuers();

        return new IssuersV2DTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> "true".equals(issuer.getEnabled()))
                .collect(Collectors.toList()));
    }

    private IssuersV2DTO getFilteredIssuers(IssuersV2DTO issuersDTO, String search) {
        if (StringUtils.isEmpty(search)) {
            return issuersDTO;
        }

        return new IssuersV2DTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getDisplay().stream()
                        .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains(search.toLowerCase())))
                .collect(Collectors.toList()));
    }

    @Override
    public IssuersV2DTO getAllIssuers() throws ApiNotAccessibleException, IOException {
        IssuersV2DTO issuersDTO;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }

        issuersDTO = objectMapper.readValue(issuersConfigJsonValue, IssuersV2DTO.class);

        return issuersDTO;
    }

    @Override
    public CredentialIssuerConfiguration getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        String credentialIssuerHost = getIssuerV2Details(issuerId).getCredentialIssuerHost();
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuersConfigUtil.getIssuerWellknown(credentialIssuerHost);

        if(credentialIssuerWellKnownResponse.getAuthorizationServers() == null || credentialIssuerWellKnownResponse.getAuthorizationServers().isEmpty()) {
            credentialIssuerWellKnownResponse.setAuthorizationServers(List.of(credentialIssuerHost));
        }
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = issuersConfigUtil.getAuthServerWellknown(credentialIssuerWellKnownResponse.getAuthorizationServers().getFirst());

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
            IssuerV2DTO issuerDTO = getIssuerV2Details(issuerId);
            CredentialIssuerWellKnownResponse wellKnownResponse = issuersConfigUtil.getIssuerWellknown(issuerDTO.getCredentialIssuerHost());
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
    public IssuersV2DTO getIssuersV2DTO() throws ApiNotAccessibleException, IOException {
        return getAllEnabledIssuers();
    }

    @Override
    public IssuerV2DTO getIssuerV2Details(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuersV2DTO issuersDTO = getAllEnabledIssuers();

        return issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getIssuerId().equals(issuerId))
                .findFirst()
                .orElseThrow(InvalidIssuerIdException::new);
    }

    /**
     * Maps an {@link IssuerV2DTO} (from config) to {@link IssuerDTO} (API response).
     */
    private IssuerDTO toIssuerDTO(IssuerV2DTO issuer) throws AuthorizationServerWellknownResponseException, ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        String issuerId = issuer.getIssuerId();
        CredentialIssuerConfiguration issuerConfiguration = getIssuerConfiguration(issuerId);
        String tokenEndpoint = issuerConfiguration.getAuthorizationServerWellKnownResponse().getTokenEndpoint();

        IssuerDTO issuerDTO = new IssuerDTO().mapFromIssuerV2DTO(issuer);
        issuerDTO.setCredential_issuer(issuerId);
        issuerDTO.setWellknown_endpoint(issuer.getCredentialIssuerHost()+"/.well-known/openid-credential-issuer");
        issuerDTO.setRedirect_uri("io.mosip.residentapp.inji://oauthredirect");
        issuerDTO.setAuthorization_audience(tokenEndpoint);
        issuerDTO.setProxy_token_endpoint(tokenEndpoint);

        return issuerDTO;
    }
}