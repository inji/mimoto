package io.mosip.mimoto.service;

import com.google.common.collect.Lists;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.AuditResponseDto;
import io.mosip.mimoto.dto.CryptoWithPinResponseDto;
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
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URI;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class CredentialShareServiceTest {

    @InjectMocks
    private CredentialShareService service = new CredentialShareServiceImpl();

    @Mock
    public RestApiClient restApiClient;

    @Mock
    public AuditLogRequestBuilder auditLogRequestBuilder;

    @Mock
    private CryptoCoreUtil cryptoCoreUtil;

    @Mock
    DerivedKeyCryptoUtil derivedKeyCryptoUtil;

    @Mock
    private Utilities utilities;

    private EventModel eventModel = null;

    @Mock
    private CbeffToBiometricUtil util;

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
        event.setData(data);
        event.setTransactionId("transactionid");
        eventModel = new EventModel();
        eventModel.setEvent(event);

        CryptoWithPinResponseDto cryptoWithPinResponseDto = new CryptoWithPinResponseDto();
        cryptoWithPinResponseDto.setData("biometrics");

        Mockito.when(derivedKeyCryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenReturn(cryptoWithPinResponseDto);
        Mockito.when(utilities.getDataPath()).thenReturn("target");
        Mockito.when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn("credential");
        Mockito.when(cryptoCoreUtil.decrypt(Mockito.anyString())).thenReturn("{\"credentialSubject\":{\"biometrics\":\"biometrics\"},\"protectedAttributes\":[\"biometrics\"]}");
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);

        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        Mockito.when(auditLogRequestBuilder.createAuditRequestBuilder(
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.any())).thenReturn(new ResponseWrapper<AuditResponseDto>());


        BIR bir = new BIR();
        BDBInfo bdbInfo = new BDBInfo();
        bdbInfo.setType(Lists.newArrayList(BiometricType.FACE));
        bir.setBdbInfo(bdbInfo);
        List<BIR> birs = Lists.newArrayList(bir);
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("face image strring".getBytes());

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

    /*@Test(expected = DocumentGeneratorException.class)
    public void documentFailedExceptionTest() throws Exception {

        Mockito.when(cryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenThrow(new Exception("exception"));

        boolean result = service.generateDocuments(eventModel);

       // assertFalse(result);

    }*/

}
