package io.mosip.mimoto.service;

import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.util.SigningKeyUtil;
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
public class DataProtectionServiceTest {

    @Mock
    private CryptomanagerService cryptomanagerService;

    @InjectMocks
    private DataProtectionService dataProtectionService;

    private final String refId = "ref123";
    private final String aad = "aad123";
    private final String salt = "salt123";
    private final String encryptedData = "encryptedData";
    private KeyPair keyPair;

    private SecretKey encryptionKey;


    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        String appId = "MIMOTO";
        ReflectionTestUtils.setField(dataProtectionService, "appId", appId);
        encryptionKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);
    }

    @Test
    public void shouldEncryptDataSuccessfully() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData(encryptedData);
        when(cryptomanagerService.encrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String data = "testData";
        String result = dataProtectionService.encrypt(data, refId, aad, salt);

        assertEquals(encryptedData, result);
    }

    @Test
    public void shouldReturnNullIfDataToEncryptIsNull() {
        String result = dataProtectionService.encrypt(null, refId, aad, salt);

        assertNull(result);
    }

    @Test
    public void shouldDecryptDataSuccessfully() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        String decryptedData = "testData";
        responseDto.setData(CryptoUtil.encodeToURLSafeBase64(decryptedData.getBytes(StandardCharsets.UTF_8)));
        when(cryptomanagerService.decrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String result = dataProtectionService.decrypt(encryptedData, refId, aad, salt);

        assertEquals(decryptedData, result);
    }

    @Test
    public void shouldReturnNullIfDataToDecryptIsNull() {
        String result = dataProtectionService.decrypt(null, refId, aad, salt);
        assertNull(result);
    }


    @Test
    public void shouldEncryptPrivateKeyWithAESSuccessfully() throws Exception {
        SecretKey aesKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        KeyPair keyPair = SigningKeyUtil.generateKeyPair(SigningAlgorithm.ED25519);

        String encryptedPrivateKey = dataProtectionService.encryptWithAES(aesKey, keyPair.getPrivate().getEncoded());

        assertNotNull(encryptedPrivateKey);
        assertFalse(StringUtils.isBlank(encryptedPrivateKey));
    }

    @Test
    public void testIVChangesButCiphertextRemainsSameForSameEncryptionKeyAndSecretKey() throws Exception {
        String encryptedPrivateKey1 = dataProtectionService.encryptWithAES(encryptionKey, keyPair.getPrivate().getEncoded());
        String encryptedPrivateKey2 = dataProtectionService.encryptWithAES(encryptionKey, keyPair.getPrivate().getEncoded());

        byte[] encryptedBytes1 = Base64.getDecoder().decode(encryptedPrivateKey1);
        byte[] encryptedBytes2 = Base64.getDecoder().decode(encryptedPrivateKey2);

        byte[] iv1 = Arrays.copyOfRange(encryptedBytes1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(encryptedBytes2, 0, 12);

        byte[] decryptedPrivateKey1Bytes = dataProtectionService.decryptWithAES(encryptionKey, encryptedPrivateKey1);
        byte[] decryptedPrivateKey2Bytes = dataProtectionService.decryptWithAES(encryptionKey, encryptedPrivateKey2);
        PrivateKey decryptedPrivateKey1 = DataProtectionService.bytesToPrivateKey(decryptedPrivateKey1Bytes, "ed25519");
        PrivateKey decryptedPrivateKey2 = DataProtectionService.bytesToPrivateKey(decryptedPrivateKey2Bytes,"ed25519");

        assertFalse(Arrays.equals(iv1, iv2), "IVs should be different");
        assertEquals(decryptedPrivateKey1, decryptedPrivateKey2);
    }

    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionWhenEncryptionFails() {
        String data = "testData";
        String refId = "refId";
        String aad = "aad";
        String salt = "salt";
        when(cryptomanagerService.encrypt(any(CryptomanagerRequestDto.class)))
                .thenThrow(new RuntimeException("Simulated encryption failure"));

        dataProtectionService.encrypt(data, refId, aad, salt);
    }


    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionWhenDecryptionFails() {
        String data = "encryptedData";
        String refId = "refId";
        String aad = "aad";
        String salt = "salt";
        when(cryptomanagerService.decrypt(any(CryptomanagerRequestDto.class)))
                .thenThrow(new RuntimeException("Simulated decryption failure"));

        dataProtectionService.decrypt(data, refId, aad, salt);
    }


    @Test
    public void shouldReturnNullIfDataToEncryptWithAESIsNull() {
        SecretKey key = encryptionKey;
        byte[] data = null;
        String result = dataProtectionService.encryptWithAES(key, data);
        assertNull(result);
    }

    @Test
    public void shouldReturnNullIfDataToEncryptWithAESEmpty() {
        SecretKey key = encryptionKey;
        byte[] data = new byte[0];
        String result = dataProtectionService.encryptWithAES(key, data);
        assertNull(result);
    }

    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionWhenEncryptWithAESFails() throws Exception {
        SecretKey badKey = new javax.crypto.spec.SecretKeySpec(new byte[8], "AES");
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        dataProtectionService.encryptWithAES(badKey, data);
    }


    @Test
    public void shouldReturnNullIfDataToDecryptWithAESIsNull() {
        SecretKey key = encryptionKey;
        String data = null;
        byte[] result = dataProtectionService.decryptWithAES(key, data);
        assertNull(result);
    }

    @Test
    public void shouldReturnNullIfDataToDecryptWithAESEmpty() {
        SecretKey key = encryptionKey;
        String data = "";
        byte[] result = dataProtectionService.decryptWithAES(key, data);
        assertNull(result);
    }

    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionIfEncryptedDataTooShort() {
        SecretKey key = encryptionKey;
        // Base64 for 5 bytes, less than NONCE_LENGTH (12)
        String shortData = Base64.getEncoder().encodeToString(new byte[5]);
        dataProtectionService.decryptWithAES(key, shortData);
    }

    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionWhenDecryptWithAESFails() {
        // Create valid encrypted data with a good key
        String plainText = "test";
        String encrypted = dataProtectionService.encryptWithAES(encryptionKey, plainText.getBytes(StandardCharsets.UTF_8));
        // Use a bad key for decryption
        SecretKey badKey = new javax.crypto.spec.SecretKeySpec(new byte[8], "AES");
        dataProtectionService.decryptWithAES(badKey, encrypted);
    }


    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfKeyBytesNull() {
        DataProtectionService.bytesToSecretKey(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfKeyBytesEmpty() {
        DataProtectionService.bytesToSecretKey(new byte[0]);
    }


    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfPrivateKeyBytesNull() throws Exception {
        DataProtectionService.bytesToPrivateKey(null, "RSA");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfPrivateKeyBytesEmpty() throws Exception {
        DataProtectionService.bytesToPrivateKey(new byte[0], "RSA");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfAlgorithmNameNull() throws Exception {
        DataProtectionService.bytesToPrivateKey(new byte[16], null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfAlgorithmNameEmpty() throws Exception {
        DataProtectionService.bytesToPrivateKey(new byte[16], "");
    }

    @Test(expected = Exception.class)
    public void shouldThrowExceptionIfKeyConversionFails() throws Exception {
        // Invalid key bytes for RSA
        byte[] invalidKey = new byte[16];
        DataProtectionService.bytesToPrivateKey(invalidKey, "RSA");
    }


    @Test(expected = EncryptionException.class)
    public void shouldThrowEncryptionExceptionIfCredentialDataNull() throws EncryptionException {
        dataProtectionService.encryptCredential(null, "validBase64Key");
    }

    @Test(expected = EncryptionException.class)
    public void shouldThrowEncryptionExceptionIfCredentialDataEmpty() throws EncryptionException {
        dataProtectionService.encryptCredential("", "validBase64Key");
    }

    @Test(expected = EncryptionException.class)
    public void shouldThrowEncryptionExceptionIfWalletKeyNull() throws EncryptionException {
        dataProtectionService.encryptCredential("credential", null);
    }

    @Test(expected = EncryptionException.class)
    public void shouldThrowEncryptionExceptionIfWalletKeyEmpty() throws EncryptionException {
        dataProtectionService.encryptCredential("credential", "");
    }

    @Test(expected = EncryptionException.class)
    public void shouldThrowEncryptionExceptionIfWalletKeyInvalid() throws EncryptionException {
        // Not a valid Base64 string
        dataProtectionService.encryptCredential("credential", "not_base64");
    }

    @Test
    public void shouldEncryptCredentialSuccessfully() throws EncryptionException {
        String credential = "credential";
        SecretKey walletKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        String base64WalletKey = Base64.getEncoder().encodeToString(walletKey.getEncoded());
        String encrypted = dataProtectionService.encryptCredential(credential, base64WalletKey);
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());
    }


    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfEncryptedCredentialDataNull() throws DecryptionException {
        dataProtectionService.decryptCredential(null, "validBase64Key");
    }

    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfEncryptedCredentialDataEmpty() throws DecryptionException {
        dataProtectionService.decryptCredential("", "validBase64Key");
    }

    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfWalletKeyNullForDecryption() throws DecryptionException {
        dataProtectionService.decryptCredential("encrypted", null);
    }

    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfWalletKeyEmptyForDecryption() throws DecryptionException {
        dataProtectionService.decryptCredential("encrypted", "");
    }

    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfWalletKeyInvalidForDecryption() throws DecryptionException {
        // Not a valid Base64 string
        dataProtectionService.decryptCredential("encrypted", "not_base64");
    }

    @Test(expected = DecryptionException.class)
    public void shouldThrowDecryptionExceptionIfDecryptionFails() throws DecryptionException {
        // Valid Base64 key, but not matching encrypted data
        SecretKey walletKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        String base64WalletKey = Base64.getEncoder().encodeToString(walletKey.getEncoded());
        dataProtectionService.decryptCredential("invalidEncryptedData", base64WalletKey);
    }

    @Test
    public void shouldDecryptCredentialSuccessfully() throws Exception {
        String credential = "credential";
        SecretKey walletKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        String base64WalletKey = Base64.getEncoder().encodeToString(walletKey.getEncoded());

        String encrypted = dataProtectionService.encryptCredential(credential, base64WalletKey);
        String decrypted = dataProtectionService.decryptCredential(encrypted, base64WalletKey);

        assertNotNull(decrypted);
        assertEquals(credential, decrypted);
    }


    @Test
    public void shouldReturnNullWhenStringToBytesInputIsNull() throws Exception {
        // Use reflection to access private static method
        java.lang.reflect.Method method = DataProtectionService.class.getDeclaredMethod("stringToBytes", String.class);
        method.setAccessible(true);
        assertNull(method.invoke(null, (Object) null));
    }

    @Test
    public void shouldReturnUtf8BytesWhenStringToBytesInputIsNotNull() throws Exception {
        java.lang.reflect.Method method = DataProtectionService.class.getDeclaredMethod("stringToBytes", String.class);
        method.setAccessible(true);
        String input = "hello";
        byte[] result = (byte[]) method.invoke(null, input);
        assertArrayEquals(input.getBytes(StandardCharsets.UTF_8), result);
    }

    @Test
    public void shouldReturnNullWhenBytesToStringInputIsNull() throws Exception {
        java.lang.reflect.Method method = DataProtectionService.class.getDeclaredMethod("bytesToString", byte[].class);
        method.setAccessible(true);
        assertNull(method.invoke(null, (Object) null));
    }

    @Test
    public void shouldReturnStringWhenBytesToStringInputIsNotNull() throws Exception {
        java.lang.reflect.Method method = DataProtectionService.class.getDeclaredMethod("bytesToString", byte[].class);
        method.setAccessible(true);
        String input = "world";
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        String result = (String) method.invoke(null, (Object) bytes);
        assertEquals(input, result);
    }


    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfHeaderJsonNull() {
        dataProtectionService.createDetachedJwtSigningInput(null, "payload");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionIfPayloadBase64UrlNull() {
        dataProtectionService.createDetachedJwtSigningInput("{}", null);
    }

    @Test(expected = RuntimeException.class)
    public void shouldThrowRuntimeExceptionIfPayloadBase64UrlInvalid() {
        // Not a valid Base64URL string
        dataProtectionService.createDetachedJwtSigningInput("{}", "!!!not_base64url!!!");
    }

    @Test
    public void shouldCreateDetachedJwtSigningInputSuccessfully() {
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";
        String payload = "test-payload";
        // Encode payload to Base64URL
        String payloadBase64Url = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        byte[] result = dataProtectionService.createDetachedJwtSigningInput(headerJson, payloadBase64Url);
        assertNotNull(result);
        // The result should contain a '.' separator
        int dotIndex = -1;
        for (int i = 0; i < result.length; i++) {
            if (result[i] == (byte)'.') {
                dotIndex = i;
                break;
            }
        }
        assertTrue(dotIndex > 0);
    }

}
