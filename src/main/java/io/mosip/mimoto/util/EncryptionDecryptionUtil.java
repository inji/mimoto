package io.mosip.mimoto.util;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.openID4VP.common.DecoderKt;
import io.mosip.openID4VP.common.EncoderKt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static io.mosip.mimoto.exception.ErrorConstants.DECRYPTION_FAILED;
import static io.mosip.mimoto.exception.ErrorConstants.ENCRYPTION_FAILED;

/**
 * Utility class for encryption and decryption operations.
 */
@Slf4j
@Component
public class EncryptionDecryptionUtil {
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH = 12; // Recommended nonce length for GCM
    private static final int TAG_LENGTH = 128; // Authentication tag length in bits (16 bytes)
    public static final String USER_PII_KEY_REFERENCE_ID = "user_pii";

    private final CryptomanagerService cryptomanagerService;

    @Value("${mosip.inji.app.id:MIMOTO}")
    private String appId;

    public EncryptionDecryptionUtil(CryptomanagerService cryptomanagerService) {
        this.cryptomanagerService = cryptomanagerService;
    }

    /**
     * Encrypts data using the provided reference ID, AAD, and salt.
     *
     * @param data   The data to encrypt.
     * @param refId  The reference ID.
     * @param aad    The additional authentication data.
     * @param salt   The salt for encryption.
     * @return The encrypted data.
     */
    public String encrypt(String data, String refId, String aad, String salt) {
        if (data == null) {
            log.warn("Encryption skipped: Input data is null");
            return null;
        }
        try {
            CryptomanagerRequestDto request = new CryptomanagerRequestDto();
            request.setApplicationId(appId);
            request.setReferenceId(refId);
            request.setData(CryptoUtil.encodeToURLSafeBase64(data.getBytes(StandardCharsets.UTF_8)));
            request.setAad(aad);
            request.setSalt(salt);
            CryptomanagerResponseDto response = cryptomanagerService.encrypt(request);
            log.debug("Data encrypted successfully for refId: {}", refId);
            return response.getData();
        } catch (Exception e) {
            log.error("Encryption failed for refId: {}", refId, e);
            throw new RuntimeException("Failed to encrypt data", e);
        }
    }

    /**
     * Decrypts data using the provided reference ID, AAD, and salt.
     *
     * @param data   The data to decrypt.
     * @param refId  The reference ID.
     * @param aad    The additional authentication data.
     * @param salt   The salt for decryption.
     * @return The decrypted data.
     */
    public String decrypt(String data, String refId, String aad, String salt) {
        if (data == null) {
            log.warn("Decryption skipped: Input data is null");
            return null;
        }
        try {
            CryptomanagerRequestDto request = new CryptomanagerRequestDto();
            request.setApplicationId(appId);
            request.setReferenceId(refId);
            request.setData(data);
            request.setAad(aad);
            request.setSalt(salt);
            CryptomanagerResponseDto response = cryptomanagerService.decrypt(request);
            String decryptedData = new String(CryptoUtil.decodeURLSafeBase64(response.getData()), StandardCharsets.UTF_8);
            log.debug("Data decrypted successfully for refId: {}", refId);
            return decryptedData;
        } catch (Exception e) {
            log.error("Decryption failed for refId: {}", refId, e);
            throw new RuntimeException("Failed to decrypt data", e);
        }
    }

    /**
     * Encrypts data with AES/GCM/NoPadding using the provided key.
     *
     * @param key  The AES key.
     * @param data The data to encrypt.
     * @return The encrypted data, including the nonce prepended, encoded in Base64.
     */
    public String encryptWithAES(SecretKey key, byte[] data) {
        if (data == null || data.length == 0) {
            log.warn("AES encryption skipped: Input data is null or empty");
            return null;
        }
        try {
            // Generate a random nonce
            byte[] nonce = new byte[NONCE_LENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(nonce);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, nonce);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            // Encrypt data
            byte[] encryptedData = cipher.doFinal(data);

            // Prepend nonce to encrypted data (nonce + ciphertext + tag)
            byte[] combined = new byte[nonce.length + encryptedData.length];
            System.arraycopy(nonce, 0, combined, 0, nonce.length);
            System.arraycopy(encryptedData, 0, combined, nonce.length, encryptedData.length);

            // Encode to Base64
            String result = Base64.getEncoder().encodeToString(combined);
            log.debug("AES/GCM encryption successful, data length: {}", data.length);
            return result;
        } catch (Exception e) {
            log.error("AES/GCM encryption failed", e);
            throw new RuntimeException("Failed to encrypt with AES/GCM", e);
        }
    }

    /**
     * Decrypts data with AES/GCM/NoPadding using the provided key.
     *
     * @param key  The AES key.
     * @param data The encrypted data (Base64-encoded, with nonce prepended).
     * @return The decrypted data.
     */
    public byte[] decryptWithAES(SecretKey key, String data) {
        if (data == null || data.isEmpty()) {
            log.warn("AES decryption skipped: Input data is null or empty");
            return null;
        }
        try {
            // Decode Base64 data
            byte[] decodedData = Base64.getDecoder().decode(data);

            // Extract nonce and encrypted data
            if (decodedData.length < NONCE_LENGTH) {
                log.error("Invalid encrypted data: too short");
                throw new IllegalArgumentException("Invalid encrypted data length");
            }
            byte[] nonce = new byte[NONCE_LENGTH];
            byte[] encryptedData = new byte[decodedData.length - NONCE_LENGTH];
            System.arraycopy(decodedData, 0, nonce, 0, NONCE_LENGTH);
            System.arraycopy(decodedData, NONCE_LENGTH, encryptedData, 0, encryptedData.length);

            // Initialize cipher
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            // Decrypt data
            byte[] decryptedData = cipher.doFinal(encryptedData);
            log.debug("AES/GCM decryption successful, decrypted length: {}", decryptedData.length);
            return decryptedData;
        } catch (Exception e) {
            log.error("AES/GCM decryption failed", e);
            throw new RuntimeException("Failed to decrypt with AES/GCM", e);
        }
    }

    /**
     * Converts a byte array to a SecretKey for AES.
     *
     * @param keyBytes The byte array representing the key.
     * @return The SecretKey.
     */
    public static SecretKey bytesToSecretKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length == 0) {
            log.error("Invalid key bytes: null or empty");
            throw new IllegalArgumentException("Key bytes cannot be null or empty");
        }
        try {
            return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            log.error("Failed to convert bytes to SecretKey", e);
            throw new RuntimeException("Failed to create SecretKey", e);
        }
    }

    /**
     * Converts a byte array to a PrivateKey for the specified algorithm.
     *
     * @param privateKeyBytes The byte array representing the private key.
     * @param algorithmName   The algorithm name (e.g., RSA, EC).
     * @return The PrivateKey.
     * @throws Exception If key conversion fails.
     */
    public static PrivateKey bytesToPrivateKey(byte[] privateKeyBytes, String algorithmName) throws Exception {
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            log.error("Invalid private key bytes: null or empty");
            throw new IllegalArgumentException("Private key bytes cannot be null or empty");
        }
        if (algorithmName == null || algorithmName.isEmpty()) {
            log.error("Invalid algorithm name: null or empty");
            throw new IllegalArgumentException("Algorithm name cannot be null or empty");
        }
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            log.error("Failed to convert bytes to PrivateKey for algorithm: {}", algorithmName, e);
            throw new Exception("Failed to create PrivateKey", e);
        }
    }

    /**
     * Encrypts a SecretKey with a user PIN.
     *
     * @param encryptionKey The SecretKey to encrypt.
     * @param pin           The user PIN.
     * @return The encrypted key data.
     */
    public String encryptKeyWithPin(SecretKey encryptionKey, String pin) {
        if (encryptionKey == null) {
            log.error("Encryption key is null");
            throw new IllegalArgumentException("Encryption key cannot be null");
        }
        if (pin == null || pin.isEmpty()) {
            log.error("PIN is null or empty");
            throw new IllegalArgumentException("PIN cannot be null or empty");
        }
        try {
            CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
            requestDto.setUserPin(pin);
            String dataAsString = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
            requestDto.setData(dataAsString);
            CryptoWithPinResponseDto responseDto = cryptomanagerService.encryptWithPin(requestDto);
            log.debug("Key encrypted with PIN successfully");
            return responseDto.getData();
        } catch (Exception e) {
            log.error("Failed to encrypt key with PIN", e);
            throw new RuntimeException("Failed to encrypt key with PIN", e);
        }
    }

    /**
     * Decrypts data using a user PIN.
     *
     * @param encryptedString The encrypted data.
     * @param pin             The user PIN.
     * @return The decrypted data.
     */
    public String decryptWithPin(String encryptedString, String pin) {
        if (encryptedString == null || encryptedString.isEmpty()) {
            log.error("Encrypted string is null or empty");
            throw new IllegalArgumentException("Encrypted string cannot be null or empty");
        }
        if (pin == null || pin.isEmpty()) {
            log.error("PIN is null or empty");
            throw new IllegalArgumentException("PIN cannot be null or empty");
        }
        try {
            CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
            requestDto.setUserPin(pin);
            requestDto.setData(encryptedString);
            CryptoWithPinResponseDto responseDto = cryptomanagerService.decryptWithPin(requestDto);
            log.debug("Data decrypted with PIN successfully");
            return responseDto.getData();
        } catch (Exception e) {
            log.error("Failed to decrypt with PIN", e);
            throw new RuntimeException("Failed to decrypt with PIN", e);
        }
    }

    /**
     * Encrypts credential data using a wallet key.
     *
     * @param credentialData        The credential data to encrypt.
     * @param base64EncodedWalletKey The Base64-encoded wallet key.
     * @return The encrypted credential data.
     * @throws EncryptionException If encryption fails.
     */
    public String encryptCredential(String credentialData, String base64EncodedWalletKey) throws EncryptionException {
        if (credentialData == null || credentialData.isEmpty()) {
            log.error("Credential data is null or empty");
            throw new EncryptionException(ENCRYPTION_FAILED.getErrorCode(), "Credential data cannot be null or empty");
        }
        if (base64EncodedWalletKey == null || base64EncodedWalletKey.isEmpty()) {
            log.error("Wallet key is null or empty");
            throw new EncryptionException(ENCRYPTION_FAILED.getErrorCode(), "Wallet key cannot be null or empty");
        }
        try {
            byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
            SecretKey walletKey = bytesToSecretKey(decodedWalletKey);
            String encryptedData = encryptWithAES(walletKey, stringToBytes(credentialData));
            log.debug("Credential encrypted successfully");
            return encryptedData;
        } catch (Exception e) {
            log.error("Failed to encrypt credential", e);
            throw new EncryptionException(ENCRYPTION_FAILED.getErrorCode(), "Failed to encrypt credential", e);
        }
    }

    /**
     * Decrypts credential data using a wallet key.
     *
     * @param encryptedCredentialData The encrypted credential data.
     * @param base64EncodedWalletKey  The Base64-encoded wallet key.
     * @return The decrypted credential data.
     * @throws DecryptionException If decryption fails.
     */
    public String decryptCredential(String encryptedCredentialData, String base64EncodedWalletKey) throws DecryptionException {
        if (encryptedCredentialData == null || encryptedCredentialData.isEmpty()) {
            log.error("Encrypted credential data is null or empty");
            throw new DecryptionException(DECRYPTION_FAILED.getErrorCode() , "Encrypted credential data cannot be null or empty");
        }
        if (base64EncodedWalletKey == null || base64EncodedWalletKey.isEmpty()) {
            log.error("Wallet key is null or empty");
            throw new DecryptionException(DECRYPTION_FAILED.getErrorCode(), "Wallet key cannot be null or empty");
        }
        try {
            byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
            SecretKey walletKey = bytesToSecretKey(decodedWalletKey);
            byte[] decryptedData = decryptWithAES(walletKey, encryptedCredentialData);
            String result = bytesToString(decryptedData);
            log.debug("Credential decrypted successfully");
            return result;
        } catch (Exception e) {
            log.error("Failed to decrypt credential", e);
            throw new DecryptionException(DECRYPTION_FAILED.getErrorCode(), "Failed to decrypt credential", e);
        }
    }

    /**
     * Converts a string to a byte array using UTF-8 encoding.
     *
     * @param data The input string.
     * @return The byte array.
     */
    private static byte[] stringToBytes(String data) {
        if (data == null) {
            return null;
        }
        return data.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Converts a byte array to a string using UTF-8 encoding.
     *
     * @param data The byte array.
     * @return The string.
     */
    private static String bytesToString(byte[] data) {
        if (data == null) {
            return null;
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Creates a detached JWT signing input by encoding the header and concatenating it with the payload bytes.
     * This is used for creating the input to sign for detached JWTs where the payload is not included in the final JWT.
     * Uses OpenID4VP library utilities for Base64URL encoding/decoding.
     * Format: base64url(header) + '.' + payload_bytes
     *
     * @param headerJson The JWT header as a JSON string.
     * @param payloadBase64Url The Base64URL encoded payload string to decode.
     * @return byte array containing header bytes + '.' + payload bytes for signing
     * @throws IllegalArgumentException if headerJson or payloadBase64Url is null
     */
    public byte[] createDetachedJwtSigningInput(String headerJson, String payloadBase64Url) {
        if (headerJson == null) {
            log.error("Header JSON cannot be null");
            throw new IllegalArgumentException("Header JSON cannot be null");
        }
        if (payloadBase64Url == null) {
            log.error("Payload Base64URL string cannot be null");
            throw new IllegalArgumentException("Payload Base64URL string cannot be null");
        }

        try {
            // Decode the Base64URL encoded payload
            byte[] payloadBytes = DecoderKt.decodeFromBase64Url(payloadBase64Url);

            // Encode the header JSON to Base64URL
            String header64 = EncoderKt.encodeToBase64Url(headerJson.getBytes(StandardCharsets.UTF_8));

            // Create input bytes for detached JWT signing: header + '.' + payload
            byte[] headerBytes = header64.getBytes(StandardCharsets.UTF_8);
            byte[] inputBytes = new byte[headerBytes.length + 1 + payloadBytes.length];
            System.arraycopy(headerBytes, 0, inputBytes, 0, headerBytes.length);
            inputBytes[headerBytes.length] = (byte) '.';
            System.arraycopy(payloadBytes, 0, inputBytes, headerBytes.length + 1, payloadBytes.length);

            log.debug("Detached JWT signing input created successfully, header length: {}, payload length: {}", 
                    headerBytes.length, payloadBytes.length);
            return inputBytes;
        } catch (Exception e) {
            log.error("Failed to create detached JWT signing input", e);
            throw new RuntimeException("Failed to create detached JWT signing input", e);
        }
    }
}