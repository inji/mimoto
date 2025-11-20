package io.mosip.mimoto.service;


import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.IOException;

public interface CredentialMatchingService {
    MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException;
}