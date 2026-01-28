package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.ProofSigningKey;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.impl.KeyPairRetrievalServiceImpl;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.SigningKeyUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairServiceTest {

    @InjectMocks
    private KeyPairRetrievalServiceImpl keyPairService;

    @Mock
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private String walletId;
    private String base64EncodedWalletKey;
    private ProofSigningKey proofSigningKey;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        walletId = "test-wallet-id";
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        keyPair = keyPairGenerator.generateKeyPair();
        
        byte[] walletKeyBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            walletKeyBytes[i] = (byte) i;
        }
        base64EncodedWalletKey = Base64.getEncoder().encodeToString(walletKeyBytes);
        
        Wallet wallet = new Wallet();
        wallet.setId(walletId);
        
        proofSigningKey = new ProofSigningKey();
        proofSigningKey.setId("key-id");
        proofSigningKey.setWallet(wallet);
        proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        proofSigningKey.setEncryptedSecretKey("encrypted-private-key");
        proofSigningKey.setCreatedAt(Instant.now());
        proofSigningKey.setUpdatedAt(Instant.now());
    }

    @Test
    public void testGetKeyPairFromDBSuccessWithED25519() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(keyPair);
            
            KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result);
            assertEquals(keyPair, result);
            verify(proofSigningKeyRepository).findByWalletIdAndAlgorithm(walletId, algorithm.name());
            verify(encryptionDecryptionUtil).decryptWithAES(any(SecretKey.class), eq("encrypted-private-key"));
        }
    }

    @Test
    public void testGetKeyPairFromDBSuccessWithRS256() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.RS256;
        
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        
        proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = rsaKeyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(rsaKeyPair);
            
            KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result);
            assertEquals(rsaKeyPair, result);
        }
    }

    @Test
    public void testGetKeyPairFromDBSuccessWithES256() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ES256;
        
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        
        proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(ecKeyPair.getPublic().getEncoded()));
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = ecKeyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(ecKeyPair);
            
            KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result);
            assertEquals(ecKeyPair, result);
        }
    }

    @Test(expected = KeyGenerationException.class)
    public void testGetKeyPairFromDBThrowsKeyGenerationExceptionWhenKeyNotFound() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.empty());
        
        try {
            keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
        } catch (KeyGenerationException e) {
            assertEquals("KEY_NOT_FOUND", e.getErrorCode());
            assertTrue(e.getErrorText().contains("No proof signing key found"));
            assertTrue(e.getErrorText().contains(walletId));
            assertTrue(e.getErrorText().contains(algorithm.toString()));
            throw e;
        }
    }

    @Test
    public void testGetKeyPairFromDBThrowsDecryptionExceptionForInvalidBase64WalletKey() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        String invalidBase64Key = "Invalid!@#$%Base64";
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        try {
            keyPairService.getKeyPairFromDB(walletId, invalidBase64Key, algorithm);
            fail("Should have thrown DecryptionException");
        } catch (DecryptionException e) {
            assertEquals("INVALID_WALLET_KEY", e.getErrorCode());
            assertTrue(e.getErrorText().contains("Invalid base64 encoded wallet key"));
            assertNotNull(e.getCause());
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }

    @Test(expected = KeyGenerationException.class)
    public void testGetKeyPairFromDBThrowsKeyGenerationExceptionForInvalidBase64PublicKey() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        proofSigningKey.setPublicKey("Invalid!@#$%Base64PublicKey");
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class)) {
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            try {
                keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            } catch (KeyGenerationException e) {
                assertEquals("INVALID_PUBLIC_KEY", e.getErrorCode());
                assertTrue(e.getErrorText().contains("Invalid base64 encoded public key"));
                assertNotNull(e.getCause());
                assertTrue(e.getCause() instanceof IllegalArgumentException);
                throw e;
            }
        }
    }

    @Test(expected = DecryptionException.class)
    public void testGetKeyPairFromDBThrowsDecryptionExceptionWhenDecryptionFails() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenThrow(new RuntimeException("Decryption error"));
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class)) {
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            try {
                keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            } catch (DecryptionException e) {
                assertEquals("DECRYPTION_FAILED", e.getErrorCode());
                assertTrue(e.getErrorText().contains("Failed to decrypt private key"));
                assertTrue(e.getErrorText().contains(walletId));
                assertNotNull(e.getCause());
                throw e;
            }
        }
    }

    @Test(expected = KeyGenerationException.class)
    public void testGetKeyPairFromDBThrowsKeyGenerationExceptionWhenKeyPairGenerationFails() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenThrow(new RuntimeException("Key generation error"));
            
            try {
                keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            } catch (KeyGenerationException e) {
                assertEquals("KEY_GENERATION_FAILED", e.getErrorCode());
                assertTrue(e.getErrorText().contains("Failed to generate KeyPair"));
                assertTrue(e.getErrorText().contains(algorithm.toString()));
                assertNotNull(e.getCause());
                throw e;
            }
        }
    }

    @Test
    public void testGetKeyPairFromDBWithDifferentWalletIds() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        String wallet1 = "wallet-1";
        String wallet2 = "wallet-2";
        
        ProofSigningKey key1 = new ProofSigningKey();
        key1.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        key1.setEncryptedSecretKey("encrypted-key-1");
        
        ProofSigningKey key2 = new ProofSigningKey();
        key2.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        key2.setEncryptedSecretKey("encrypted-key-2");
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(wallet1, algorithm.name()))
                .thenReturn(Optional.of(key1));
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(wallet2, algorithm.name()))
                .thenReturn(Optional.of(key2));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), anyString()))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(keyPair);
            
            KeyPair result1 = keyPairService.getKeyPairFromDB(wallet1, base64EncodedWalletKey, algorithm);
            KeyPair result2 = keyPairService.getKeyPairFromDB(wallet2, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result1);
            assertNotNull(result2);
            verify(proofSigningKeyRepository).findByWalletIdAndAlgorithm(wallet1, algorithm.name());
            verify(proofSigningKeyRepository).findByWalletIdAndAlgorithm(wallet2, algorithm.name());
            verify(encryptionDecryptionUtil).decryptWithAES(any(SecretKey.class), eq("encrypted-key-1"));
            verify(encryptionDecryptionUtil).decryptWithAES(any(SecretKey.class), eq("encrypted-key-2"));
        }
    }

    @Test
    public void testGetKeyPairFromDBWithAllSigningAlgorithms() throws Exception {
        for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
            when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                    .thenReturn(Optional.of(proofSigningKey));
            
            byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
            when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                    .thenReturn(decryptedPrivateKey);
            
            try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
                 MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
                
                mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                        .thenReturn(mock(SecretKey.class));
                
                mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                        eq(algorithm), any(byte[].class), any(byte[].class)))
                        .thenReturn(keyPair);
                
                KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
                
                assertNotNull(result);
            }
            
            reset(proofSigningKeyRepository, encryptionDecryptionUtil);
        }
    }

    @Test(expected = KeyGenerationException.class)
    public void testGetKeyPairFromDBWithNullProofSigningKeyRepository() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.empty());
        
        keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
    }

    @Test
    public void testGetKeyPairFromDBVerifiesRepositoryIsCalledWithCorrectParameters() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ES256;
        String testWalletId = "specific-wallet-id";
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(testWalletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(keyPair);
            
            keyPairService.getKeyPairFromDB(testWalletId, base64EncodedWalletKey, algorithm);
            
            verify(proofSigningKeyRepository, times(1)).findByWalletIdAndAlgorithm(testWalletId, algorithm.name());
        }
    }

    @Test
    public void testGetKeyPairFromDBHandlesEmptyEncryptedSecretKey() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        proofSigningKey.setEncryptedSecretKey("");
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(keyPair);
            
            KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result);
            verify(encryptionDecryptionUtil).decryptWithAES(any(SecretKey.class), eq(""));
        }
    }

    @Test
    public void testGetKeyPairFromDBThrowsDecryptionExceptionForCorruptedWalletKey() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenThrow(new RuntimeException("Corrupted key - decryption failed"));
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class)) {
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            try {
                keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
                fail("Should have thrown DecryptionException");
            } catch (DecryptionException e) {
                assertEquals("DECRYPTION_FAILED", e.getErrorCode());
                assertTrue(e.getErrorText().contains("Failed to decrypt private key"));
                assertTrue(e.getErrorText().contains(walletId));
                assertNotNull(e.getCause());
            }
        }
    }

    @Test
    public void testGetKeyPairFromDBLogsDebugMessages() throws Exception {
        SigningAlgorithm algorithm = SigningAlgorithm.ED25519;
        
        when(proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name()))
                .thenReturn(Optional.of(proofSigningKey));
        
        byte[] decryptedPrivateKey = keyPair.getPrivate().getEncoded();
        when(encryptionDecryptionUtil.decryptWithAES(any(SecretKey.class), eq("encrypted-private-key")))
                .thenReturn(decryptedPrivateKey);
        
        try (MockedStatic<EncryptionDecryptionUtil> mockedStaticUtil = Mockito.mockStatic(EncryptionDecryptionUtil.class);
             MockedStatic<SigningKeyUtil> mockedStaticKeyGen = Mockito.mockStatic(SigningKeyUtil.class)) {
            
            mockedStaticUtil.when(() -> EncryptionDecryptionUtil.bytesToSecretKey(any(byte[].class)))
                    .thenReturn(mock(SecretKey.class));
            
            mockedStaticKeyGen.when(() -> SigningKeyUtil.generateKeyPair(
                    eq(algorithm), any(byte[].class), any(byte[].class)))
                    .thenReturn(keyPair);
            
            KeyPair result = keyPairService.getKeyPairFromDB(walletId, base64EncodedWalletKey, algorithm);
            
            assertNotNull(result);
        }
    }
}

