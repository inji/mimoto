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
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private Utilities utilities;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IssuerConfigUtil issuersConfigUtil;

    @Override
    @Cacheable(value = "issuersConfig", key = "#p0 ?: 'allIssuersConfig'")
    public IssuersDTO getIssuers() throws ApiNotAccessibleException, IOException {
        return getAllEnabledIssuers(getAllIssuers());
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
    public IssuersV2DTO getIssuersV2DTO() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO = getIssuers();
        List<IssuerV2DTO> list = issuersDTO.getIssuers().parallelStream().map(this::toIssuerV2DTO).collect(Collectors.toList());
        return new IssuersV2DTO(list);
    }

    public IssuerV2DTO getIssuerV2Details(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = getIssuerDetails(issuerId);
        return toIssuerV2DTO(issuerDTO);
    }

    /**
     * Maps an {@link IssuerDTO} (from config) to {@link IssuerV2DTO} (API response).
     */
    private IssuerV2DTO toIssuerV2DTO(IssuerDTO issuer) {

        return IssuerV2DTO.builder()
                .issuerId(issuer.getIssuer_id())
                .protocol(issuer.getProtocol())
                .display(issuer.getDisplay())
                .clientId(issuer.getClient_id())
                .tokenEndpoint(issuer.getToken_endpoint())
                .clientAlias(issuer.getClient_alias())
                .qrCodeType(issuer.getQr_code_type())
                .enabled(issuer.getEnabled())
                .credentialIssuerHost(issuer.getCredential_issuer_host())
                .build();
    }
}