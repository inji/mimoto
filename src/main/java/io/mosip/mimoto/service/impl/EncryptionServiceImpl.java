package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.service.DataProtectionService;
import io.mosip.mimoto.service.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EncryptionServiceImpl implements EncryptionService {
    private static final String USER_PII_KEY_REFERENCE_ID = "user_pii";
    private static final String EMPTY_AAD = "";
    private static final String EMPTY_SALT = "";

    private final DataProtectionService dataProtectionService;

    @Autowired
    public EncryptionServiceImpl(DataProtectionService dataProtectionService) {
        this.dataProtectionService = dataProtectionService;
    }

    @Override
    public String encrypt(String data) throws EncryptionException {
        return dataProtectionService.encrypt(data, USER_PII_KEY_REFERENCE_ID, EMPTY_AAD, EMPTY_SALT);
    }

    @Override
    public String decrypt(String data) throws DecryptionException {
        return dataProtectionService.decrypt(data, USER_PII_KEY_REFERENCE_ID, EMPTY_AAD, EMPTY_SALT);
    }
}
