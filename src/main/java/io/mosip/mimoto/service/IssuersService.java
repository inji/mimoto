package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.IssuersV2DTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.constraints.NotBlank;

import java.io.IOException;

public interface IssuersService {
    IssuersDTO getIssuers(String search) throws ApiNotAccessibleException, IOException;

    IssuerDTO getIssuerDetails(String issuerId) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException;

    IssuersDTO getAllIssuers() throws ApiNotAccessibleException, IOException;

    CredentialIssuerConfiguration getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException;

    CredentialIssuerWellKnownResponse getIssuerWellKnownResponse(String credentialIssuerHost) throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException;

    IssuerConfig getIssuerConfig(String issuerId, @NotBlank String credentialType) throws ApiNotAccessibleException, InvalidIssuerIdException;

    IssuersV2DTO getIssuersV2DTO() throws ApiNotAccessibleException, IOException;

    IssuerV2DTO getIssuerV2Details(String issuerId) throws ApiNotAccessibleException, IOException;
}
