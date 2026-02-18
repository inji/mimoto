package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerResponseDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.constraints.NotBlank;

import java.io.IOException;
import java.util.List;

public interface IssuersService {
    IssuersDTO getIssuers(String search) throws ApiNotAccessibleException, IOException;

    IssuerDTO getIssuerDetails(String issuerId) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException;

    IssuersDTO getAllIssuers() throws ApiNotAccessibleException, IOException;

    CredentialIssuerConfiguration getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException;

    IssuerConfig getIssuerConfig(String issuerId, @NotBlank String credentialType) throws ApiNotAccessibleException, InvalidIssuerIdException;

    List<IssuerResponseDTO> getIssuersResponse(String search) throws ApiNotAccessibleException, IOException;

    IssuerResponseDTO getIssuerResponseDetails(String issuerId) throws ApiNotAccessibleException, IOException;
}
