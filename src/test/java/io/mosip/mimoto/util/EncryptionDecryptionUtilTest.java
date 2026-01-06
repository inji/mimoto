package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.mimoto.constant.SigningAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EncryptionDecryptionUtilTest {

    @Mock
    private CryptomanagerService cryptomanagerService;

    @InjectMocks
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private final String refId = "ref123";
    private final String aad = "aad123";
    private final String salt = "salt123";
    private final String encryptedData = "encryptedData";
    private KeyPair keyPair;

    private SecretKey encryptionKey;


    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        String appId = "MIMOTO";
        ReflectionTestUtils.setField(encryptionDecryptionUtil, "appId", appId);
        encryptionKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);
    }

    @Test
    public void shouldEncryptDataSuccessfully() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData(encryptedData);
        when(cryptomanagerService.encrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String data = "testData";
        String result = encryptionDecryptionUtil.encrypt(data, refId, aad, salt);

        assertEquals(encryptedData, result);
    }

    @Test
    public void shouldReturnNullIfDataToEncryptIsNull() {
        String result = encryptionDecryptionUtil.encrypt(null, refId, aad, salt);

        assertNull(result);
    }

    @Test
    public void shouldDecryptDataSuccessfully() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        String decryptedData = "testData";
        responseDto.setData(CryptoUtil.encodeToURLSafeBase64(decryptedData.getBytes(StandardCharsets.UTF_8)));
        when(cryptomanagerService.decrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String result = encryptionDecryptionUtil.decrypt(encryptedData, refId, aad, salt);

        assertEquals(decryptedData, result);
    }

    @Test
    public void shouldReturnNullIfDataToDecryptIsNull() {
        String result = encryptionDecryptionUtil.decrypt(null, refId, aad, salt);
        assertNull(result);
    }


    @Test
    public void shouldEncryptPrivateKeyWithAESSuccessfully() throws Exception {
        SecretKey aesKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);

        String encryptedPrivateKey = encryptionDecryptionUtil.encryptWithAES(aesKey, keyPair.getPrivate().getEncoded());

        assertNotNull(encryptedPrivateKey);
        assertFalse(StringUtils.isBlank(encryptedPrivateKey));
    }

    @Test
    public void testIVChangesButCiphertextRemainsSameForSameEncryptionKeyAndSecretKey() throws Exception {
        String encryptedPrivateKey1 = encryptionDecryptionUtil.encryptWithAES(encryptionKey, keyPair.getPrivate().getEncoded());
        String encryptedPrivateKey2 = encryptionDecryptionUtil.encryptWithAES(encryptionKey, keyPair.getPrivate().getEncoded());

        byte[] encryptedBytes1 = Base64.getDecoder().decode(encryptedPrivateKey1);
        byte[] encryptedBytes2 = Base64.getDecoder().decode(encryptedPrivateKey2);

        byte[] iv1 = Arrays.copyOfRange(encryptedBytes1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(encryptedBytes2, 0, 12);

        byte[] decryptedPrivateKey1Bytes = encryptionDecryptionUtil.decryptWithAES(encryptionKey, encryptedPrivateKey1);
        byte[] decryptedPrivateKey2Bytes = encryptionDecryptionUtil.decryptWithAES(encryptionKey, encryptedPrivateKey2);
        PrivateKey decryptedPrivateKey1 = EncryptionDecryptionUtil.bytesToPrivateKey(decryptedPrivateKey1Bytes, "ed25519");
        PrivateKey decryptedPrivateKey2 = EncryptionDecryptionUtil.bytesToPrivateKey(decryptedPrivateKey2Bytes,"ed25519");

        assertFalse(Arrays.equals(iv1, iv2), "IVs should be different");
        assertEquals(decryptedPrivateKey1, decryptedPrivateKey2);
    }
}
