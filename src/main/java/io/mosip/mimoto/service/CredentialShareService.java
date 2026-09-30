package io.mosip.mimoto.service;

import io.mosip.mimoto.model.EventModel;

import java.io.IOException;

public interface CredentialShareService {

    /**
     * Generate documents from websub event model.
     *
     * @param eventModel
     * @return
     * @throws IOException
     */
    public boolean generateDocuments(EventModel eventModel) throws IOException;
}