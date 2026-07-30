package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.constants.SpecVersion;

import java.io.IOException;

public interface PresentationService {

    String processVPRequest(PresentationRequestDTO presentationRequestDTO, SpecVersion specVersion) throws ApiNotAccessibleException, IOException;
}
