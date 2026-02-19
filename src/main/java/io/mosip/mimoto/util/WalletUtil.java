package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.ProofSigningKey;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.DataProtectionService;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Component
@Slf4j
public class WalletUtil {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private DataProtectionService dataProtectionService;

    @Autowired
    private CryptomanagerService cryptomanagerService;

    public String decryptWalletKey(String encryptedWalletKey, String pin) {
        try {
            return decryptWithPin(encryptedWalletKey, pin);
        } catch (Exception e) {
            throw new InvalidRequestException(INVALID_PIN.getErrorCode(), INVALID_PIN.getErrorMessage() + " " + e);
        }
    }

    public String createWallet(String userId, String walletName, String pin) {
        SecretKey encryptionKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        return saveWallet(userId, walletName, pin, encryptionKey, "AES", "encryptWithPin");
    }

    public String saveWallet(String userId, String walletName, String walletPin, SecretKey encryptionKey, String encryptionAlgorithm, String encryptionType) {

        String walletId = UUID.randomUUID().toString();
        PasscodeControl passcodeControl = new PasscodeControl();
        WalletMetadata walletMetadata = createWalletMetadata(walletName, encryptionAlgorithm, encryptionType, passcodeControl);
        String walletKey = encryptKeyWithPin(encryptionKey, walletPin);
        Wallet newWallet = Wallet.builder()
                .id(walletId)
                .userId(userId)
                .walletMetadata(walletMetadata)
                .walletKey(walletKey)
                .build();

        List<ProofSigningKey> proofSigningKeys = createProofSigningKeys(encryptionKey, newWallet);
        newWallet.setProofSigningKeys(proofSigningKeys);

        walletRepository.save(newWallet);
        return walletId;
    }

    private WalletMetadata createWalletMetadata(String walletName, String encryptionAlgorithm, String encryptionType, PasscodeControl passcodeControl) {
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setEncryptionAlgo(encryptionAlgorithm);
        walletMetadata.setEncryptionType(encryptionType);
        walletMetadata.setName(walletName);
        walletMetadata.setLockStatus(null);
        walletMetadata.setPasscodeControl(passcodeControl);
        return walletMetadata;
    }

    private List<ProofSigningKey> createProofSigningKeys(SecretKey encryptionKey, Wallet wallet) {
        List<ProofSigningKey> proofSigningKeys = new ArrayList<>();
        List<SigningAlgorithm> algorithms = List.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.ES256K, SigningAlgorithm.ED25519);
        for (SigningAlgorithm algorithm : algorithms) {
            ProofSigningKey signingKey = SigningKeyUtil.createProofSigningKey(algorithm);
            signingKey.setWallet(wallet);
            signingKey.setEncryptedSecretKey(dataProtectionService.encryptWithAES(encryptionKey,
                    signingKey.getSecretKey().getEncoded()));
            proofSigningKeys.add(signingKey);
        }
        return proofSigningKeys;
    }

    public static String getSessionWalletKey(HttpSession session) {
        Object key = session.getAttribute(SessionKeys.WALLET_KEY);
        if (key == null)
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Wallet key not found in session");
        return key.toString();
    }

    public static void validateWalletId(HttpSession session, String walletIdFromRequest) {
        Object sessionWalletId = session.getAttribute(SessionKeys.WALLET_ID);
        if (sessionWalletId == null)
            throw new InvalidRequestException(WALLET_LOCKED.getErrorCode(), WALLET_LOCKED.getErrorMessage());

        String walletIdInSession = sessionWalletId.toString();
        if (!walletIdInSession.equals(walletIdFromRequest)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Invalid Wallet ID. Session and request Wallet ID do not match");
        }
    }

    /**
     * Encrypts a SecretKey with a user PIN.
     *
     * @param encryptionKey The SecretKey to encrypt.
     * @param pin           The user PIN.
     * @return The encrypted key data.
     */
    private String encryptKeyWithPin(SecretKey encryptionKey, String pin) {
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
    private String decryptWithPin(String encryptedString, String pin) {
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
}