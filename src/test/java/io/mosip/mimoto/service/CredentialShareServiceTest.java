package io.mosip.mimoto.service;

import com.google.common.collect.Lists;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.CryptoWithPinResponseDto;
import io.mosip.mimoto.exception.DocumentGeneratorException;
import io.mosip.mimoto.exception.IdentityNotFoundException;
import io.mosip.mimoto.model.Event;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import io.mosip.mimoto.util.*;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.URI;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialShareServiceTest {

    @Spy
    @InjectMocks
    private CredentialShareServiceImpl service;

    @Mock
    public RestApiClient restApiClient;

    @Mock
    public AuditLogRequestBuilder auditLogRequestBuilder;

    @Mock
    private P12KeyStoreManager p12KeyStoreManager;

    @Mock
    DerivedKeyCryptoUtil derivedKeyCryptoUtil;

    @Mock
    private Utilities utilities;

    @Mock
    private WebSubSubscriptionHelper webSubSubscriptionHelper;

    @Mock
    private DataShareUtil dataShareUtil;

    @Mock
    private RestClientService<Object> restClientService;

    @Mock
    private org.springframework.core.env.Environment env;

    @Mock
    private io.mosip.kernel.core.websub.spi.PublisherClient<String, Object, HttpHeaders> pb;

    @Mock
    private CbeffToBiometricUtil util;

    private EventModel eventModel = null;

    @Before
    public void setup() throws Exception {
        Map<String, String> proofMap = new HashMap<>();
        proofMap.put("signature", "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJQUzI1NiJ9..XSGdtAvEdcSrdHiyC8pP8orML1v3akfHru821aMVNKSa9ftx3DIS1ZbqNL-DNxWmdLjcINpsWIbwyD7Lbn0MZNIsmR5SjJJa31cB710aFpMfQgHY0R2cgh8XJWIU4Whs8Tvt9RWJ2la0CkIdeukEjxKQs2Ier1x3wzbVSK6OeoYO6tM77saDsDciu88JGRLt5zdkNyc9hN0XNwH3SPG1hJOKV4QUHW3CzIFGKvcR-VZHD7iAyqrgVNjEt1IU7ghdqH38xiTZ-2QfJDkH90yUmUEkHJ-AcXlFZATIi3YYPY9UNSBEZeHaN-fOwrPETftTo6a_DZiYIYeW1eYVs_hvnA\",\n" +
                "        \"proofPurpose\": \"assertionMethod");
        Map<String, Object> data = new HashMap<>();
        data.put("credential", "credential");
        data.put("protectionKey", "12345");
        data.put("credentialType", "VERCRED");
        data.put("proof", proofMap);

        Event event = new Event();
        event.setDataShareUri("https://www.datashare.com");
        event.setTransactionId("transactionid");
        event.setData(data);

        eventModel = new EventModel();
        eventModel.setEvent(event);

        CryptoWithPinResponseDto cryptoWithPinResponseDto = new CryptoWithPinResponseDto();
        cryptoWithPinResponseDto.setData("biometrics");

        Mockito.when(derivedKeyCryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenReturn(cryptoWithPinResponseDto);
        Mockito.when(utilities.getDataPath()).thenReturn("target");
        Mockito.when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn("credential");
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn("{\"credentialSubject\":{\"biometrics\":\"biometrics\"},\"protectedAttributes\":[\"biometrics\"]}");

        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        Mockito.when(auditLogRequestBuilder.createAuditRequestBuilder(
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.any())).thenReturn(new ResponseWrapper<>());

        BIR bir = new BIR();
        BDBInfo bdbInfo = new BDBInfo();
        bdbInfo.setType(Lists.newArrayList(BiometricType.FACE));
        bir.setBdbInfo(bdbInfo);
        List<BIR> birs = Lists.newArrayList(bir);
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("face image strring".getBytes());

        service = new CredentialShareServiceImpl(restApiClient, webSubSubscriptionHelper, dataShareUtil,
                derivedKeyCryptoUtil, p12KeyStoreManager, util, auditLogRequestBuilder, utilities,
                restClientService, env, pb);

    }

    @Test
    public void generateDocumentsTest() throws Exception {

        boolean result = service.generateDocuments(eventModel);

        assertTrue(result);
    }

    @Test
    public void documentExceptionTest() throws Exception {

        Mockito.when(derivedKeyCryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenThrow(new InvalidKeyException("exception"));

        boolean result = service.generateDocuments(eventModel);

        assertFalse(result);

    }

    @Test
    public void generateDocumentsWithNullDataShareUriTest() throws Exception {
        eventModel.getEvent().setDataShareUri(null);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
        Mockito.verify(restApiClient, Mockito.never()).getApi(Mockito.any(URI.class), Mockito.any(Class.class));
    }

    @Test
    public void generateDocumentsWithEmptyDataShareUriTest() throws Exception {
        eventModel.getEvent().setDataShareUri("");
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
        Mockito.verify(restApiClient, Mockito.never()).getApi(Mockito.any(URI.class), Mockito.any(Class.class));
    }

    @Test
    public void generateDocumentsWithUINTest() throws Exception {
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString()))
                .thenReturn("{\"credentialSubject\":{\"UIN\":\"1234567890\",\"biometrics\":\"biometrics\"},\"protectedAttributes\":[\"biometrics\"]}");
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithVIDTest() throws Exception {
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString()))
                .thenReturn("{\"credentialSubject\":{\"PCN\":\"9876543210\",\"biometrics\":\"biometrics\"},\"protectedAttributes\":[\"biometrics\"]}");
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithExceptionInGetDocumentsTest() throws Exception {
        Mockito.reset(p12KeyStoreManager);
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString()))
                .thenThrow(new RuntimeException("Decryption failed"));
        boolean result = service.generateDocuments(eventModel);
        assertFalse(result);
    }

    @Test
    public void generateDocumentsWithNullCredentialJSONTest() throws Exception {
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString()))
                .thenReturn("{\"credentialSubject\":null,\"protectedAttributes\":[]}");
        boolean result = service.generateDocuments(eventModel);
        assertFalse(result);
    }

    @Test
    public void generateDocumentsWithArrayListFieldTest() throws Exception {
        String credentialWithArrayList = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometrics\"," +
                "\"name\":[{\"language\":\"eng\",\"value\":\"John Doe\"},{\"language\":\"ara\",\"value\":\"جون دو\"}]" +
                "},\"protectedAttributes\":[\"biometrics\"]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithArrayList);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "name");
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithMultiLanguageFieldsFilteredBySupportedLang() throws Exception {
        String credentialWithMultiLang = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometrics\"," +
                "\"fullName\":[" +
                "{\"language\":\"eng\",\"value\":\"John Smith\"}," +
                "{\"language\":\"ara\",\"value\":\"جون سميث\"}," +
                "{\"language\":\"fra\",\"value\":\"Jean Smith\"}" +
                "]" +
                "},\"protectedAttributes\":[\"biometrics\"]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithMultiLang);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "fullName");
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithNullProtectedAttributesInDecryptAttribute() throws Exception {
        String credentialWithNullProtectedAttrs = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometrics\"," +
                "\"fullName\":\"Test User\"" +
                "},\"protectedAttributes\":null}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithNullProtectedAttrs);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "fullName");
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithEmptyProtectedAttributesInDecryptAttribute() throws Exception {
        String credentialWithEmptyProtectedAttrs = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometrics\"," +
                "\"fullName\":\"Test User\"" +
                "},\"protectedAttributes\":[]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithEmptyProtectedAttrs);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "fullName");
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithLinkedHashMapFieldTest() throws Exception {
        String credentialWithLinkedHashMap = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometrics\"," +
                "\"dateOfBirth\":{\"value\":\"1990/01/01\"}" +
                "},\"protectedAttributes\":[\"biometrics\"]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithLinkedHashMap);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "dateOfBirth");
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithBiometricsKeyTest() throws Exception {
        String credentialWithBiometrics = "{\"credentialSubject\":{" +
                "\"biometrics\":\"encodedBiometricData\"," +
                "\"fullName\":\"Test User\"" +
                "},\"protectedAttributes\":[\"biometrics\"]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithBiometrics);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        templateMap.put("demographics", "fullName");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithMultipleTemplateFieldsTest() throws Exception {
        String credentialWithMultipleFields = "{\"credentialSubject\":{" +
                "\"biometrics\":\"biometricData\"," +
                "\"fullName\":\"Jane Smith\"," +
                "\"address\":[{\"language\":\"eng\",\"value\":\"123 Main St\"},{\"language\":\"ara\",\"value\":\"123 الشارع الرئيسي\"}]," +
                "\"gender\":{\"value\":\"Female\"}" +
                "},\"protectedAttributes\":[\"biometrics\"]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithMultipleFields);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        templateMap.put("demographics", "fullName,address,gender");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithNullIndividualBiometricTest() throws Exception {
        String credentialWithNullBiometrics = "{\"credentialSubject\":{" +
                "\"biometrics\":null," +
                "\"fullName\":\"Test User\"" +
                "},\"protectedAttributes\":[]}";
        Mockito.when(p12KeyStoreManager.decrypt(Mockito.anyString())).thenReturn(credentialWithNullBiometrics);
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        templateMap.put("demographics", "fullName");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithEmptyBIRTypeListTest() throws Exception {
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(Lists.newArrayList());
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithNullPhotoBytesTest() throws Exception {
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(null);
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithEmptySubTypeTest() throws Exception {
        BIR bir = new BIR();
        BDBInfo bdbInfo = new BDBInfo();
        bdbInfo.setType(Lists.newArrayList(BiometricType.FINGER));
        bdbInfo.setSubtype(Lists.newArrayList());
        bir.setBdbInfo(bdbInfo);
        List<BIR> birs = Lists.newArrayList(bir);
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn("finger image with empty subtype".getBytes());
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithNonEmptySubTypeTest() throws Exception {
        BIR bir = new BIR();
        BDBInfo bdbInfo = new BDBInfo();
        bdbInfo.setType(Lists.newArrayList(BiometricType.FINGER));
        bdbInfo.setSubtype(Lists.newArrayList("Left", "Thumb"));
        bir.setBdbInfo(bdbInfo);
        List<BIR> birs = Lists.newArrayList(bir);
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("finger image with subtype".getBytes());
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithMultipleBiometricTypesTest() throws Exception {
        BIR faceBir = new BIR();
        BDBInfo faceBdbInfo = new BDBInfo();
        faceBdbInfo.setType(Lists.newArrayList(BiometricType.FACE));
        faceBdbInfo.setSubtype(Lists.newArrayList());
        faceBir.setBdbInfo(faceBdbInfo);

        BIR fingerBir = new BIR();
        BDBInfo fingerBdbInfo = new BDBInfo();
        fingerBdbInfo.setType(Lists.newArrayList(BiometricType.FINGER));
        fingerBdbInfo.setSubtype(Lists.newArrayList("Left", "IndexFinger"));
        fingerBir.setBdbInfo(fingerBdbInfo);

        BIR irisBir = new BIR();
        BDBInfo irisBdbInfo = new BDBInfo();
        irisBdbInfo.setType(Lists.newArrayList(BiometricType.IRIS));
        irisBdbInfo.setSubtype(Lists.newArrayList("Right"));
        irisBir.setBdbInfo(irisBdbInfo);

        List<BIR> birs = Lists.newArrayList(faceBir, fingerBir, irisBir);

        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.lenient().when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.eq("face"), Mockito.any()))
                .thenReturn("face image data".getBytes());
        Mockito.lenient().when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.eq("finger"), Mockito.any()))
                .thenReturn("finger image data".getBytes());
        Mockito.lenient().when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.eq("iris"), Mockito.any()))
                .thenReturn("iris image data".getBytes());

        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void generateDocumentsWithBiometricProcessingExceptionTest() throws Exception {
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenThrow(new RuntimeException("Biometric processing error"));
        boolean result = service.generateDocuments(eventModel);
        assertTrue(result);
    }

    @Test
    public void testGetDocumentsWithVidOnly() throws Exception {
        ReflectionTestUtils.setField(service, "vid", "PCN");

        org.json.JSONObject credentialJson = new org.json.JSONObject();
        credentialJson.put("biometrics", "dummyBiometric");
        credentialJson.put("PCN", "9876543210");

        Mockito.doReturn(new org.json.JSONObject()).when(service).getBiometricsDataJSON(Mockito.anyString());

        Map<String, byte[]> result = service.getDocuments(credentialJson, "VERCRED", "req-123", "dummySign");

        assertNotNull(result);
        assertTrue(result.containsKey(CredentialShareServiceImpl.UIN_TEXT_FILE));
    }

    @Test(expected = DocumentGeneratorException.class)
    public void testGetDocumentsThrowsDocumentGeneratorExceptionAndSetsFailureAudit() throws Exception {
        org.json.JSONObject credentialJson = new org.json.JSONObject();
        credentialJson.put("UIN", "1234567890");
        credentialJson.put("biometrics", "dummyBiometric");

        Mockito.doThrow(new RuntimeException("forced failure"))
                .when(service).createJSONFile(Mockito.any(org.json.JSONObject.class), Mockito.anyString());

        service.getDocuments(credentialJson, "VERCRED", "req-456", "dummySign");
    }

    @Test(expected = IdentityNotFoundException.class)
    public void testCreateJSONFileWithNullCredential() throws Exception {
        service.createJSONFile(null, "biometricData");
    }

    @Test
    public void testCreateJSONFileWithArrayListField() throws Exception {
        org.json.JSONObject credential = new org.json.JSONObject();
        credential.put("fullName", new org.json.JSONArray(
                java.util.Arrays.asList(
                        new org.json.JSONObject("{\"language\":\"eng\",\"value\":\"John\"}"),
                        new org.json.JSONObject("{\"language\":\"fra\",\"value\":\"Jean\"}")
                )
        ));

        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "fullName,nonExistentKey");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        byte[] result = service.createJSONFile(credential, null);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void testCreateJSONFileWithLinkedHashMapField() throws Exception {
        org.json.JSONObject credential = new org.json.JSONObject(
                "{\"gender\":{\"value\":\"Male\"}}"
        );

        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "gender");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        byte[] result = service.createJSONFile(credential, null);

        assertNotNull(result);
        String output = new String(result);
        assertTrue(output.contains("Male"));
    }

    @Test
    public void testCreateJSONFileWithMissingTemplateKey() throws Exception {
        org.json.JSONObject credential = new org.json.JSONObject();
        credential.put("fullName", "John Doe");

        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("demographics", "nonExistentField");
        JSONObject templateJSON = new JSONObject(templateMap);
        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        byte[] result = service.createJSONFile(credential, null);

        assertNotNull(result);
        assertTrue(result.length > 0);
        String output = new String(result);
        assertFalse("Missing key should not appear in output", output.contains("nonExistentField"));
    }


    @Test
    public void testGetBiometricsDataJSONWithNullInput() {
        org.json.JSONObject result = service.getBiometricsDataJSON(null);

        assertNotNull(result);
        assertEquals(0, result.length());
    }

    private static byte[] buildValidFaceRecord(byte[] imagePayload) throws Exception {
        ByteArrayOutputStream repBaos = new ByteArrayOutputStream();
        DataOutputStream repDos = new DataOutputStream(repBaos);

        repDos.write(new byte[14]);
        repDos.writeByte(1);
        repDos.write(new byte[5]);
        repDos.writeShort(1);
        repDos.write(new byte[15]);
        repDos.write(new byte[8]);
        repDos.writeByte(0);
        repDos.writeByte(0);
        repDos.write(new byte[9]);
        repDos.writeInt(imagePayload.length);
        repDos.write(imagePayload);
        repDos.flush();
        byte[] repData = repBaos.toByteArray();

        ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
        DataOutputStream outerDos = new DataOutputStream(outerBaos);
        outerDos.write(new byte[4]);
        outerDos.write(new byte[4]);
        outerDos.writeInt(0);
        outerDos.writeShort(1);
        outerDos.writeByte(0);
        outerDos.write(new byte[2]);
        outerDos.writeInt(repData.length + 4);
        outerDos.write(repData);
        outerDos.flush();
        return outerBaos.toByteArray();
    }

    private static byte[] buildValidFaceRecordNoQualityNoLandmarks(byte[] imagePayload) throws Exception {
        ByteArrayOutputStream repBaos = new ByteArrayOutputStream();
        DataOutputStream repDos = new DataOutputStream(repBaos);

        repDos.write(new byte[14]);
        repDos.writeByte(0);
        repDos.writeShort(0);
        repDos.write(new byte[15]);
        repDos.writeByte(0);
        repDos.writeByte(0);
        repDos.write(new byte[9]);
        repDos.writeInt(imagePayload.length);
        repDos.write(imagePayload);
        repDos.flush();
        byte[] repData = repBaos.toByteArray();

        ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
        DataOutputStream outerDos = new DataOutputStream(outerBaos);
        outerDos.write(new byte[4]);
        outerDos.write(new byte[4]);
        outerDos.writeInt(0);
        outerDos.writeShort(1);
        outerDos.writeByte(0);
        outerDos.write(new byte[2]);
        outerDos.writeInt(repData.length + 4);
        outerDos.write(repData);
        outerDos.flush();
        return outerBaos.toByteArray();
    }

    private CredentialShareServiceImpl buildTestService() {
        CredentialShareServiceImpl testService = new CredentialShareServiceImpl();
        ReflectionTestUtils.setField(testService, "util", util);
        return testService;
    }

    @Test
    public void testExtractFaceImageDataWithQualityBlocksAndLandmarkPoints() throws Exception {
        byte[] expectedImage = "FAKE_JPEG_DATA".getBytes();
        byte[] faceRecord = buildValidFaceRecord(expectedImage);

        CredentialShareServiceImpl testService = buildTestService();

        byte[] result = ReflectionTestUtils.invokeMethod(testService, "extractFaceImageData", faceRecord);

        assertNotNull(result);
        assertArrayEquals(expectedImage, result);
    }

    @Test
    public void testExtractFaceImageDataWithNoQualityBlocksAndNoLandmarkPoints() throws Exception {
        byte[] expectedImage = "FAKE_JPEG_NO_Q_L".getBytes();
        byte[] faceRecord = buildValidFaceRecordNoQualityNoLandmarks(expectedImage);

        CredentialShareServiceImpl testService = buildTestService();

        byte[] result = ReflectionTestUtils.invokeMethod(testService, "extractFaceImageData", faceRecord);

        assertNotNull(result);
        assertArrayEquals(expectedImage, result);
    }

    @SuppressWarnings("unchecked")
    private <T> T[] invokeMapJsonNodeToJavaObject(Class<T> type,
            org.json.simple.JSONArray array) throws Exception {
        java.lang.reflect.Method m = CredentialShareServiceImpl.class.getDeclaredMethod(
                "mapJsonNodeToJavaObject", Class.class, org.json.simple.JSONArray.class);
        m.setAccessible(true);
        return (T[]) m.invoke(service, type, array);
    }

    @Test
    public void testMapJsonNodeToJavaObject_happyPath_withLinkedHashMapEntries() throws Exception {
        ReflectionTestUtils.setField(service, "supportedLang", "eng,ara");

        java.util.LinkedHashMap<String, Object> engMap = new java.util.LinkedHashMap<>();
        engMap.put("language", "eng");
        engMap.put("value", "John");

        java.util.LinkedHashMap<String, Object> fraMap = new java.util.LinkedHashMap<>();
        fraMap.put("language", "fra");
        fraMap.put("value", "Jean");

        org.json.simple.JSONArray node = new org.json.simple.JSONArray();
        node.add(engMap);
        node.add(fraMap);

        io.mosip.mimoto.dto.JsonValue[] result =
                invokeMapJsonNodeToJavaObject(io.mosip.mimoto.dto.JsonValue.class, node);

        assertNotNull(result);
        assertEquals(2, result.length);
        assertEquals("eng", ReflectionTestUtils.getField(result[0], "language"));
        assertEquals("John", ReflectionTestUtils.getField(result[0], "value"));
        assertEquals("fra", ReflectionTestUtils.getField(result[1], "language"));
        assertEquals("Jean", ReflectionTestUtils.getField(result[1], "value"));
    }

    @Test
    public void testMapJsonNodeToJavaObject_nullObjectInArray() throws Exception {
        org.json.simple.JSONArray node = new org.json.simple.JSONArray();
        node.add(null);

        io.mosip.mimoto.dto.JsonValue[] result =
                invokeMapJsonNodeToJavaObject(io.mosip.mimoto.dto.JsonValue.class, node);

        assertNotNull(result);
        assertEquals(1, result.length);
        assertNull(result[0]);
    }

    @Test
    public void testMapJsonNodeToJavaObject_throwsInstantanceCreationException() throws Exception {
        java.util.LinkedHashMap<String, Object> entry = new java.util.LinkedHashMap<>();
        entry.put("language", "eng");
        entry.put("value", "test");

        org.json.simple.JSONArray node = new org.json.simple.JSONArray();
        node.add(entry);

        java.lang.reflect.Method m = CredentialShareServiceImpl.class.getDeclaredMethod(
                "mapJsonNodeToJavaObject", Class.class, org.json.simple.JSONArray.class);
        m.setAccessible(true);

        try {
            m.invoke(service, Integer.class, node);
            fail("Expected InstantanceCreationException wrapped in InvocationTargetException");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(
                    "Expected InstantanceCreationException but got: " + e.getCause(),
                    e.getCause() instanceof io.mosip.mimoto.exception.InstantanceCreationException);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testMapJsonNodeToJavaObject_throwsFieldNotFoundException_onSecurityException() throws Exception {
        org.json.simple.JSONArray securityThrowingArray = new org.json.simple.JSONArray() {
            @Override
            public int size() {
                return 1;
            }

            @Override
            public Object get(int index) {
                throw new SecurityException("simulated security restriction");
            }
        };

        java.lang.reflect.Method m = CredentialShareServiceImpl.class.getDeclaredMethod(
                "mapJsonNodeToJavaObject", Class.class, org.json.simple.JSONArray.class);
        m.setAccessible(true);

        try {
            m.invoke(service, io.mosip.mimoto.dto.JsonValue.class, securityThrowingArray);
            fail("Expected FieldNotFoundException wrapped in InvocationTargetException");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(
                    "Expected FieldNotFoundException but got: " + e.getCause(),
                    e.getCause() instanceof io.mosip.mimoto.exception.FieldNotFoundException);
        }
    }
}
