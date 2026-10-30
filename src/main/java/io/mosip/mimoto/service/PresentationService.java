package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.constants.SpecVersion;

import java.io.IOException;

public interface PresentationService {

    String processVPRequest(PresentationRequestDTO presentationRequestDTO, SpecVersion specVersion) throws ApiNotAccessibleException, IOException;

    /**
     * Posts an authorization error to the verifier {@code response_uri} and returns the URL
     * the browser should be redirected to, if it is registered for {@code clientId}.
     * The verifier response {@code redirect_uri} is used when present.
     */
    String submitErrorToResponseUri(String clientId, String responseUri, String redirectUri, String state,
                                     String errorCode, String errorDescription);

    /**
     * After Direct Post the verifier may return a redirect URI with query or
     * {@code #response_code}. Those are stripped from the received URI; registered
     * {@code redirect_uris} have none. Return the original URI if the remaining path
     * equals a registered entry, otherwise {@code null}.
     */
    String validateRedirectUri(String clientId, String redirectUri);
}
