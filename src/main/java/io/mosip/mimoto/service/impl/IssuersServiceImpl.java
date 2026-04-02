package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.IssuersV2DTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.IssuerConfigUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.beans.factory.annotation.Value;

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

    private final String mosipApiPublicUrl;

    private final String contextPath;

    private static final String GET_TOKEN_PATH = "/get-token/";

    public IssuersServiceImpl(Utilities utilities, ObjectMapper objectMapper, IssuerConfigUtil issuersConfigUtil,
                              @Value("${mosip.api.public.url}") String mosipApiPublicUrl,
                              @Value("${server.servlet.context-path}") String contextPath) {
        this.utilities = utilities;
        this.objectMapper = objectMapper;
        this.issuersConfigUtil = issuersConfigUtil;
        this.mosipApiPublicUrl = mosipApiPublicUrl;
        this.contextPath = contextPath;
    }

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

        if (issuersDTO != null && issuersDTO.getIssuers() != null) {
            for (IssuerDTO issuer : issuersDTO.getIssuers()) {
                if (issuer != null) {
                    buildTokenEndpoint(issuer);
                }
            }
        }

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
    public IssuersV2DTO getIssuersV2DTO() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO = getIssuers(null);
        List<IssuerV2DTO> list = issuersDTO.getIssuers().parallelStream().map(this::toIssuerV2DTO).collect(Collectors.toList());
        return new IssuersV2DTO(list);
    }

    @Override
    public IssuerV2DTO getIssuerV2Details(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = getIssuerDetails(issuerId);
        return toIssuerV2DTO(issuerDTO);
    }

    /**
     * Maps an {@link IssuerDTO} (from config) to {@link IssuerV2DTO} (API response).
     */
    private IssuerV2DTO toIssuerV2DTO(IssuerDTO issuer) {

        IssuerV2DTO issuerV2DTO= new  IssuerV2DTO();

        issuerV2DTO.setIssuerId(issuer.getIssuer_id());
        issuerV2DTO.setProtocol(issuer.getProtocol());
        issuerV2DTO.setDisplay(issuer.getDisplay());
        issuerV2DTO.setClientId(issuer.getClient_id());
        issuerV2DTO.setTokenEndpoint(issuer.getToken_endpoint());
        issuerV2DTO.setClientAlias(issuer.getClient_alias());
        issuerV2DTO.setQrCodeType(issuer.getQr_code_type());
        issuerV2DTO.setEnabled(issuer.getEnabled());
        issuerV2DTO.setCredentialIssuerHost(issuer.getCredential_issuer_host());

        return issuerV2DTO;
    }

    /**
    * Builds the token_endpoint for the issuer if it is not already set in the config.
    */
    private void buildTokenEndpoint(IssuerDTO issuer) {
        if (StringUtils.isBlank(issuer.getToken_endpoint())) {
            String generatedTokenEndpoint = mosipApiPublicUrl + contextPath + GET_TOKEN_PATH + issuer.getIssuer_id();
            issuer.setToken_endpoint(generatedTokenEndpoint);
        }
    }
}