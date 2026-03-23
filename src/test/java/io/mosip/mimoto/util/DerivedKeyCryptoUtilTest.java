package io.mosip.mimoto.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import io.mosip.mimoto.dto.CryptoWithPinRequestDto;
import io.mosip.mimoto.dto.CryptoWithPinResponseDto;
import io.mosip.mimoto.exception.CryptoManagerException;
import io.mosip.mimoto.exception.ParseException;

@ExtendWith(MockitoExtension.class)
class DerivedKeyCryptoUtilTest {

    private DerivedKeyCryptoUtil derivedKeyCryptoUtil;

    private static final String AES_KEY_TYPE = "AES";
    private static final String TEST_DATA = "testdata";
    private static final String USER_PIN = "12345";
    private static final byte[] SALT = "testsalt123456789012345678901234".getBytes();
    private static final byte[] NONCE = "testnonce123".getBytes();
    private static final int DEFAULT_KEY_SIZE = 256;
    private static final int DEFAULT_ITERATIONS = 100000;
    private static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA512";

    @BeforeEach
    void setUp() {
        derivedKeyCryptoUtil = new DerivedKeyCryptoUtil(DEFAULT_KEY_SIZE, DEFAULT_ITERATIONS, DEFAULT_ALGORITHM);
    }

    private byte[] encrypt(String data, SecretKey key, byte[] nonce, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(data.getBytes());
    }

    @Test
    void testDecryptWithPin() throws Exception {
        SecretKey derivedKey = getDerivedKey(USER_PIN, SALT);
        byte[] encryptedData = encrypt(TEST_DATA, derivedKey, NONCE, SALT);

        byte[] combined = new byte[SALT.length + NONCE.length + encryptedData.length];
        System.arraycopy(SALT, 0, combined, 0, SALT.length);
        System.arraycopy(NONCE, 0, combined, SALT.length, NONCE.length);
        System.arraycopy(encryptedData, 0, combined, SALT.length + NONCE.length, encryptedData.length);

        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData(Base64.getEncoder().encodeToString(combined));
        requestDto.setUserPin(USER_PIN);

        CryptoWithPinResponseDto response = derivedKeyCryptoUtil.decryptWithPin(requestDto);
        assertNotNull(response);
        assertEquals(TEST_DATA, response.getData());
    }

    @Test
    void testSymmetricDecryptWithIV() throws Exception {
        SecretKey key = new SecretKeySpec("testkey123456789".getBytes(), AES_KEY_TYPE);
        byte[] encryptedData = encrypt(TEST_DATA, key, NONCE, null);

        byte[] decryptedData = invokeSymmetricDecrypt(key, encryptedData, NONCE, null);
        assertEquals(TEST_DATA, new String(decryptedData));
    }

    @Test
    void testSymmetricDecryptWithIVAndAad() throws Exception {
        SecretKey key = new SecretKeySpec("testkey123456789".getBytes(), AES_KEY_TYPE);
        byte[] aad = "testaad".getBytes();
        byte[] encryptedData = encrypt(TEST_DATA, key, NONCE, aad);

        byte[] decryptedData = invokeSymmetricDecrypt(key, encryptedData, NONCE, aad);
        assertEquals(TEST_DATA, new String(decryptedData));
    }

    @Test
    void testSymmetricDecryptWithIVWithNullIV() throws Exception {
        SecretKey key = new SecretKeySpec("testkey123456789".getBytes(), AES_KEY_TYPE);
        byte[] iv16 = "testnonce1234567".getBytes();
        byte[] encryptedData = encrypt(TEST_DATA, key, iv16, null);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] combined = new byte[encryptedData.length + cipher.getBlockSize()];
        System.arraycopy(encryptedData, 0, combined, 0, encryptedData.length);
        System.arraycopy(iv16, 0, combined, encryptedData.length, iv16.length);


        byte[] decryptedData = invokeSymmetricDecrypt(key, combined, null, null);
        assertEquals(TEST_DATA, new String(decryptedData));
    }

    @Test
    void testSymmetricDecryptWithIVWithNullIVAndAad() throws Exception {
        SecretKey key = new SecretKeySpec("testkey123456789".getBytes(), AES_KEY_TYPE);
        byte[] aad = "testaad".getBytes();
        byte[] iv16 = "testnonce1234567".getBytes(); // 16 bytes
        byte[] encryptedData = encrypt(TEST_DATA, key, iv16, aad);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] combined = new byte[encryptedData.length + cipher.getBlockSize()];
        System.arraycopy(encryptedData, 0, combined, 0, encryptedData.length);
        System.arraycopy(iv16, 0, combined, encryptedData.length, iv16.length);


        byte[] decryptedData = invokeSymmetricDecrypt(key, combined, null, aad);
        assertEquals(TEST_DATA, new String(decryptedData));
    }

    @Test
    void testSymmetricDecryptWithIVThrowsInvalidKeyException() throws Exception {
        SecretKey key = new SecretKeySpec("testkey".getBytes(), AES_KEY_TYPE);
        byte[] data = "testdata".getBytes();
        byte[] iv = "testiv".getBytes();
        byte[] aad = "testaad".getBytes();

        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> {
            invokeSymmetricDecrypt(key, data, iv, aad);
        });

        assertEquals(InvalidKeyException.class, exception.getTargetException().getClass());
    }

    @Test
    void testSymmetricDecryptWithoutIVThrowsCryptoManagerException() throws Exception {
        SecretKey key = new SecretKeySpec("testkey12345678901234567".getBytes(), AES_KEY_TYPE);
        byte[] data = "testdata".getBytes();
        byte[] aad = "testaad".getBytes();

        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> {
            invokeSymmetricDecrypt(key, data, null, aad);
        });

        assertEquals(CryptoManagerException.class, exception.getTargetException().getClass());
    }

    @Test
    void testSymmetricDecryptThrowsCryptoManagerException() throws Exception {
        SecretKey key = new SecretKeySpec("0123456789ABCDEF".getBytes(), AES_KEY_TYPE);
        byte[] iv = NONCE;
        byte[] encrypted = encrypt(TEST_DATA, key, iv, null);

        try (MockedStatic<Cipher> mocked = Mockito.mockStatic(Cipher.class)) {
            mocked.when(() -> Cipher.getInstance("AES/GCM/NoPadding"))
                  .thenThrow(new NoSuchAlgorithmException("for tests"));

            InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> {
                invokeSymmetricDecrypt(key, encrypted, iv, null);
            });

            Throwable targetException = exception.getTargetException();
            assertEquals(CryptoManagerException.class, targetException.getClass());
            assertTrue(targetException.getCause() instanceof NoSuchAlgorithmException);
        }
    }

    @Test
    void testGetDerivedKey() throws Exception {
        SecretKey derivedKey = getDerivedKey(USER_PIN, SALT);
        assertNotNull(derivedKey);
        assertEquals(AES_KEY_TYPE, derivedKey.getAlgorithm());
    }

    @Test
    void testHash() throws Exception {
        String hash = invokeHash(USER_PIN.getBytes(), SALT);
        assertNotNull(hash);
    }

    @Test
    void testHashThrowsCryptoManagerException() {
        derivedKeyCryptoUtil = new DerivedKeyCryptoUtil(DEFAULT_KEY_SIZE, DEFAULT_ITERATIONS, "InvalidAlgo");
        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> {
            invokeHash(USER_PIN.getBytes(), SALT);
        });
        assertEquals(CryptoManagerException.class, exception.getTargetException().getClass());
    }

    @Test
    void testHexDecode() throws Exception {
        String hexData = "7465737464617461";
        byte[] decodedBytes = invokeHexDecode(hexData);
        assertEquals(TEST_DATA, new String(decodedBytes));
    }

    @Test
    void testHexDecodeWithOddLength() {
        String hexData = "7465737464617461F";
        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> {
            invokeHexDecode(hexData);
        });
        assertEquals(ParseException.class, exception.getTargetException().getClass());
    }

    @Test
    void testStaticSymmetricDecryptWithEmptyAadDoesNotUseAad() throws Exception {
        SecretKey key = new SecretKeySpec("testkey123456789".getBytes(), AES_KEY_TYPE);
        byte[] iv16 = "testnonce1234567".getBytes();
        byte[] encryptedData = encrypt(TEST_DATA, key, iv16, null);

        byte[] combined = new byte[encryptedData.length + iv16.length];
        System.arraycopy(encryptedData, 0, combined, 0, encryptedData.length);
        System.arraycopy(iv16, 0, combined, encryptedData.length, iv16.length);

        Method staticMethod = DerivedKeyCryptoUtil.class.getDeclaredMethod("symmetricDecrypt", SecretKey.class, byte[].class, byte[].class);
        staticMethod.setAccessible(true);
        byte[] decrypted = (byte[]) staticMethod.invoke(null, key, combined, new byte[0]);
        assertEquals(TEST_DATA, new String(decrypted));
    }

    private byte[] invokeSymmetricDecrypt(SecretKey key, byte[] data, byte[] iv, byte[] aad) throws Exception {
        Method method = DerivedKeyCryptoUtil.class.getDeclaredMethod("symmetricDecrypt", SecretKey.class, byte[].class, byte[].class, byte[].class);
        method.setAccessible(true);
        return (byte[]) method.invoke(derivedKeyCryptoUtil, key, data, iv, aad);
    }

    private SecretKey getDerivedKey(String userPin, byte[] salt) throws Exception {
        Method method = DerivedKeyCryptoUtil.class.getDeclaredMethod("getDerivedKey", String.class, byte[].class);
        method.setAccessible(true);
        return (SecretKey) method.invoke(derivedKeyCryptoUtil, userPin, salt);
    }

    private String invokeHash(byte[] data, byte[] salt) throws Exception {
        Method method = DerivedKeyCryptoUtil.class.getDeclaredMethod("hash", byte[].class, byte[].class);
        method.setAccessible(true);
        return (String) method.invoke(derivedKeyCryptoUtil, data, salt);
    }

    private byte[] invokeHexDecode(String hexData) throws Exception {
        Method method = DerivedKeyCryptoUtil.class.getDeclaredMethod("hexDecode", String.class);
        method.setAccessible(true);
        return (byte[]) method.invoke(derivedKeyCryptoUtil, hexData);
    }
}
