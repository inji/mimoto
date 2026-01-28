package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@Slf4j
class WalletUtilTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @InjectMocks
    private WalletUtil walletUtil;

    private String pin;
    private String name;
    private String userId;
    private SecretKey encryptionKey;
    private String encryptedPrivateKey;
    private String encryptedWalletKey;
    private String decryptedWalletKey;
    private String encryptionAlgorithm;
    private String encryptionType;

    @BeforeEach
    void setUp() {
        // Ensure BouncyCastle provider is registered (required for ES256K algorithm)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        pin = "1234";
        name = "default";
        userId = UUID.randomUUID().toString();
        encryptionKey = SigningKeyUtil.generateEncryptionKey("AES", 256);
        encryptedPrivateKey = "encryptedPrivateKey";
        encryptedWalletKey = "encryptedWalletKey";
        decryptedWalletKey = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
        encryptionAlgorithm = "AES";
        encryptionType = "encryptWithPin";
    }

    @Test
    void shouldDecryptWalletKeySuccessfully() {
        when(encryptionDecryptionUtil.decryptWithPin(encryptedWalletKey, pin)).thenReturn(decryptedWalletKey);

        String decrypted = walletUtil.decryptWalletKey(encryptedWalletKey, pin);

        assertEquals(decryptedWalletKey, decrypted);
    }

    @Test
    void shouldThrowErrorWhenDecryptionOfWalletKeyFails() {
        when(encryptionDecryptionUtil.decryptWithPin(encryptedWalletKey, pin)).thenThrow(new RuntimeException("Failed to decrypt with PIN"));

        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> walletUtil.decryptWalletKey(encryptedWalletKey, pin));
        assertEquals("invalid_pin", ex.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN or wallet key provided java.lang.RuntimeException: Failed to decrypt with PIN", ex.getMessage());
    }


    @Test
    void shouldCreateNewWalletSuccessfully() {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.saveWallet(userId, name, pin, encryptionKey, encryptionAlgorithm, encryptionType);

        assertNotNull(walletId);
    }

    @Test
    void shouldCreateEd25519WalletSuccessfully() {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.createWallet(userId, name, pin);

        assertNotNull(walletId);
    }

    @Test
    void shouldVerifyWalletObjectOnCreateNewWallet() {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.saveWallet(userId, name, pin, encryptionKey, encryptionAlgorithm, encryptionType);

        ArgumentCaptor<Wallet> walletCaptor = ArgumentCaptor.forClass(Wallet.class);
        verify(walletRepository).save(walletCaptor.capture());

        Wallet savedWallet = walletCaptor.getValue();

        assertEquals(walletId, savedWallet.getId());
        assertEquals(userId, savedWallet.getUserId());
        assertEquals(name, savedWallet.getWalletMetadata().getName());
        assertEquals(encryptedWalletKey, savedWallet.getWalletKey());
        assertEquals(encryptionAlgorithm, savedWallet.getWalletMetadata().getEncryptionAlgo());
        assertEquals(encryptionType, savedWallet.getWalletMetadata().getEncryptionType());
        assertNotNull(savedWallet.getProofSigningKeys());
        assertEquals(4, savedWallet.getProofSigningKeys().size());
    }

    @Test
    void testValidWalletId() {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(SessionKeys.WALLET_ID)).thenReturn("wallet-123");
        assertDoesNotThrow(() -> WalletUtil.validateWalletId(session, "wallet-123"));
    }

    @Test
    void testMissingWalletIdInSession() {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(SessionKeys.WALLET_ID)).thenReturn(null);
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> WalletUtil.validateWalletId(session, "wallet-123"));
        assertEquals("wallet_locked", ex.getErrorCode());
        assertEquals("wallet_locked --> Wallet is locked", ex.getMessage());
    }

    @Test
    void testMismatchedWalletId() {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(SessionKeys.WALLET_ID)).thenReturn("wallet-abc");
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> WalletUtil.validateWalletId(session, "wallet-123"));
        assertEquals("invalid_request", ex.getErrorCode());
        assertEquals("invalid_request --> Invalid Wallet ID. Session and request Wallet ID do not match", ex.getMessage());
    }

    @Test
    void testNonStringWalletIdInSession() {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(SessionKeys.WALLET_ID)).thenReturn(12345);
        assertDoesNotThrow(() -> WalletUtil.validateWalletId(session, "12345"));
    }
}
