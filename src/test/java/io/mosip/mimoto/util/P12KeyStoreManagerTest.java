package io.mosip.mimoto.util;

import io.mosip.mimoto.exception.CryptoManagerException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class P12KeyStoreManagerTest {

    @InjectMocks
    private P12KeyStoreManager p12KeyStoreManager;

    private KeyPair keyPair;
    private KeyStore.PrivateKeyEntry privateKeyEntry;
    private SecretKey symmetricKey;
    private static final String KEY_SPLITTER = "#KEY_SPLITTER#";
    private static final byte[] VERSION_RSA_2048 = "VER_R2".getBytes();
    private static final int THUMBPRINT_LENGTH = 32;
    private static final int NONCE = 12;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        Certificate certificate = generateSelfSignedCertificate(keyPair);
        Certificate[] certChain = new Certificate[]{certificate};
        privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certChain);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        symmetricKey = keyGen.generateKey();

        ReflectionTestUtils.setField(p12KeyStoreManager, "fileName", "test.p12");
        ReflectionTestUtils.setField(p12KeyStoreManager, "cyptoPassword", "test123");
        ReflectionTestUtils.setField(p12KeyStoreManager, "alias", "testalias");
        ReflectionTestUtils.setField(p12KeyStoreManager, "isThumbprint", true);
    }

    private java.security.cert.X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        java.util.Date startDate = new java.util.Date(now);
        org.bouncycastle.asn1.x500.X500Name dnName = new org.bouncycastle.asn1.x500.X500Name("CN=Test");
        java.math.BigInteger certSerialNumber = java.math.BigInteger.valueOf(now);

        java.util.Calendar calendar = java.util.Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(java.util.Calendar.YEAR, 1);
        java.util.Date endDate = calendar.getTime();

        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder certBuilder =
            new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        org.bouncycastle.operator.ContentSigner contentSigner =
            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA")
                .build(keyPair.getPrivate());

        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Test
    public void testDecrypt_Success() throws Exception {
        String plainText = "Test Data";
        P12KeyStoreManager spyManager = spy(p12KeyStoreManager);
        doReturn(privateKeyEntry).when(spyManager).loadP12();
        doReturn(plainText.getBytes()).when(spyManager).decryptData(any(byte[].class), any(KeyStore.PrivateKeyEntry.class));

        String result = spyManager.decrypt(Base64.encodeBase64String("test".getBytes()));

        assertEquals(plainText, result);
    }

    @Test
    public void testDecrypt_WithNullData() throws Exception {
        String result = p12KeyStoreManager.decrypt(null);
        assertNull(result);
    }

    @Test
    public void testDecrypt_ExceptionHandling() throws Exception {
        P12KeyStoreManager spyManager = spy(p12KeyStoreManager);
        doThrow(new IOException("Test exception")).when(spyManager).loadP12();

        String result = spyManager.decrypt("invalid_data");
        assertNull(result);
    }

    @Test
    public void testLoadP12_FileNotFound() throws Exception {
        KeyStore.PrivateKeyEntry entry = p12KeyStoreManager.loadP12("nonexistent.p12", "alias", "password");
        assertNull(entry);
    }

    @Test
    public void testLoadP12_InvalidFile() throws Exception {
        java.io.File tempFile = java.io.File.createTempFile("invalid", ".p12");
        tempFile.deleteOnExit();
        try {
            try (java.io.FileWriter writer = new java.io.FileWriter(tempFile)) {
                writer.write("Not a valid PKCS12 file");
            }

            KeyStore.PrivateKeyEntry entry = p12KeyStoreManager.loadP12(tempFile.getAbsolutePath(), "alias", "password");
            assertNull(entry);
        } finally {
            // Ensure cleanup even if writer.write(...) or loadP12(...) throws
            tempFile.delete();
        }
    }

    @Test
    public void testDecryptData_InvalidFormat() throws Exception {
        byte[] invalidData = "invalid_data_no_splitter".getBytes();
        byte[] result = p12KeyStoreManager.decryptData(invalidData, privateKeyEntry);
        assertNull(result);
    }

    @Test
    public void testDecryptData_WithNullPrivateKey() throws Exception {
        byte[] data = ("key" + KEY_SPLITTER + "data").getBytes();
        byte[] result = p12KeyStoreManager.decryptData(data, null);
        assertNull(result);
    }

    @Test
    public void testParseEncryptKeyHeader_WithVersionHeader() {
        byte[] encryptedKey = new byte[THUMBPRINT_LENGTH + VERSION_RSA_2048.length + 256];
        System.arraycopy(VERSION_RSA_2048, 0, encryptedKey, 0, VERSION_RSA_2048.length);

        byte[] result = p12KeyStoreManager.parseEncryptKeyHeader(encryptedKey);
        assertArrayEquals(VERSION_RSA_2048, result);
    }

    @Test
    public void testParseEncryptKeyHeader_WithoutVersionHeader() {
        byte[] encryptedKey = new byte[THUMBPRINT_LENGTH + 256];
        Arrays.fill(encryptedKey, (byte) 0);

        byte[] result = p12KeyStoreManager.parseEncryptKeyHeader(encryptedKey);
        assertEquals(0, result.length);
    }

    @Test
    public void testGetCertificateThumbprint_Success() throws Exception {
        Certificate mockCert = mock(Certificate.class);
        when(mockCert.getEncoded()).thenReturn("test certificate data".getBytes());

        byte[] thumbprint = P12KeyStoreManager.getCertificateThumbprint(mockCert);

        assertNotNull(thumbprint);
        assertEquals(32, thumbprint.length);
    }

    @Test(expected = CryptoManagerException.class)
    public void testGetCertificateThumbprint_Exception() throws Exception {
        Certificate mockCert = mock(Certificate.class);
        when(mockCert.getEncoded()).thenThrow(new java.security.cert.CertificateEncodingException("Test exception"));

        P12KeyStoreManager.getCertificateThumbprint(mockCert);
    }

    @Test
    public void testSymmetricDecrypt_Success() throws Exception {
        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        byte[] nonce = new byte[NONCE];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);

        byte[] result = p12KeyStoreManager.symmetricDecrypt(symmetricKey, encryptedBytes, nonce, null);

        assertNotNull(result);
        assertEquals(plainText, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testSymmetricDecrypt_WithAAD() throws Exception {
        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        byte[] nonce = new byte[NONCE];
        new SecureRandom().nextBytes(nonce);
        byte[] aad = new byte[32];
        System.arraycopy(nonce, 0, aad, 0, NONCE);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);

        byte[] result = p12KeyStoreManager.symmetricDecrypt(symmetricKey, encryptedBytes, nonce, aad);

        assertNotNull(result);
        assertEquals(plainText, new String(result, StandardCharsets.UTF_8));
    }

    @Test(expected = CryptoManagerException.class)
    public void testSymmetricDecrypt_WrongKey() throws Exception {
        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey differentKey = keyGen.generateKey();

        p12KeyStoreManager.symmetricDecrypt(differentKey, encryptedBytes, nonce, null);
    }

    @Test
    public void testAsymmetricDecrypt_PrivateMethod() throws Exception {
        String plainText = "Test Symmetric Key";
        byte[] plainBytes = plainText.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        javax.crypto.spec.OAEPParameterSpec oaepParams = new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaepParams);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);

        java.lang.reflect.Method method = P12KeyStoreManager.class.getDeclaredMethod("asymmetricDecrypt",
                java.security.PrivateKey.class, java.math.BigInteger.class, byte[].class);
        method.setAccessible(true);

        byte[] result = (byte[]) method.invoke(null, keyPair.getPrivate(),
                ((java.security.interfaces.RSAPrivateKey) keyPair.getPrivate()).getModulus(), encryptedBytes);

        assertNotNull(result);
        assertArrayEquals(plainBytes, result);
    }

    @Test
    public void testSymmetricDecrypt_PrivateMethod() throws Exception {
        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] aad = "additional data".getBytes();
        cipher.updateAAD(aad);
        byte[] encryptedData = cipher.doFinal(plainBytes);

        java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
        outputStream.write(encryptedData);
        outputStream.write(iv);
        byte[] dataWithIV = outputStream.toByteArray();

        java.lang.reflect.Method method = P12KeyStoreManager.class.getDeclaredMethod("symmetricDecrypt",
                SecretKey.class, byte[].class, byte[].class);
        method.setAccessible(true);

        byte[] result = (byte[]) method.invoke(null, symmetricKey, dataWithIV, aad);

        assertNotNull(result);
        assertEquals(plainText, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecryptData_WithThumbprint_NoVersionHeader() throws Exception {
        ReflectionTestUtils.setField(p12KeyStoreManager, "isThumbprint", true);

        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encryptedData = aesCipher.doFinal(plainBytes);

        java.io.ByteArrayOutputStream dataStream = new java.io.ByteArrayOutputStream();
        dataStream.write(encryptedData);
        dataStream.write(iv);
        byte[] fullEncryptedData = dataStream.toByteArray();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        javax.crypto.spec.OAEPParameterSpec oaepParams = new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaepParams);
        byte[] encryptedSymmetricKey = rsaCipher.doFinal(symmetricKey.getEncoded());

        java.io.ByteArrayOutputStream keyStream = new java.io.ByteArrayOutputStream();
        keyStream.write(new byte[32]); // THUMBPRINT_LENGTH = 32
        keyStream.write(encryptedSymmetricKey);
        byte[] fullEncryptedKey = keyStream.toByteArray();

        java.io.ByteArrayOutputStream finalStream = new java.io.ByteArrayOutputStream();
        finalStream.write(fullEncryptedKey);
        finalStream.write("#KEY_SPLITTER#".getBytes());
        finalStream.write(fullEncryptedData);
        byte[] finalData = finalStream.toByteArray();

        byte[] result = p12KeyStoreManager.decryptData(finalData, privateKeyEntry);

        assertNotNull(result);
        assertEquals(plainText, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecryptData_WithoutThumbprint_NoVersionHeader() throws Exception {
        ReflectionTestUtils.setField(p12KeyStoreManager, "isThumbprint", false);

        String plainText = "Test Data";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getEncoded(), "AES");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encryptedData = aesCipher.doFinal(plainBytes);

        java.io.ByteArrayOutputStream dataStream = new java.io.ByteArrayOutputStream();
        dataStream.write(encryptedData);
        dataStream.write(iv);
        byte[] fullEncryptedData = dataStream.toByteArray();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        javax.crypto.spec.OAEPParameterSpec oaepParams = new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaepParams);
        byte[] encryptedSymmetricKey = rsaCipher.doFinal(symmetricKey.getEncoded());

        java.io.ByteArrayOutputStream finalStream = new java.io.ByteArrayOutputStream();
        finalStream.write(encryptedSymmetricKey);
        finalStream.write("#KEY_SPLITTER#".getBytes());
        finalStream.write(fullEncryptedData);
        byte[] finalData = finalStream.toByteArray();

        byte[] result = p12KeyStoreManager.decryptData(finalData, privateKeyEntry);

        assertNotNull(result);
        assertEquals(plainText, new String(result, StandardCharsets.UTF_8));
    }
}
