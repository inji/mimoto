package io.mosip.mimoto.service.impl;

import com.google.gson.Gson;
import io.mosip.biometrics.util.CommonUtil;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.mimoto.constant.*;
import io.mosip.mimoto.dto.CryptoWithPinRequestDto;
import io.mosip.mimoto.dto.CryptoWithPinResponseDto;
import io.mosip.mimoto.dto.JsonValue;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.CredentialShareService;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Slf4j
@Service
public class CredentialShareServiceImpl implements CredentialShareService {
    public static final String VC_REQUEST_FILE_NAME = "%s.json";
    public static final String EVENT_JSON_FILE_NAME = "%s_EVENT.json";
    public static final String VC_JSON_FILE_NAME = "%s_VC.json";
    public static final String CARD_JSON_FILE_NAME = "%s_VCD.json";

    /** The Constant FINGER. */
    public static final String FINGER = "Finger";
    public static final String DATA_IMAGE_JPG_BASE_64 = "data:image/jpg;base64,";
    public static final String DATA_BINARY_BASE_64 = "data:binary;base64,";

    private Gson gson = new Gson();

    public String topic = "CREDENTIAL_STATUS_UPDATE";

    @Autowired
    public WebSubSubscriptionHelper webSubSubscriptionHelper;

    @Autowired
    public DataShareUtil dataShareUtil;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    public RestApiClient restApiClient;

    @Autowired
    public CryptoCoreUtil cryptoCoreUtil;

    @Autowired
    CbeffToBiometricUtil util;

    /** The Constant VALUE. */
    public static final String VALUE = "value";

    /** The Constant UIN_TEXT_FILE. */
    public static final String UIN_TEXT_FILE = "textFile";

    @Value("${vercred.type.vid:PCN}")
    private String vid;

    /** The core audit request builder. */
    @Autowired
    private AuditLogRequestBuilder auditLogRequestBuilder;

    /** The utilities. */
    @Autowired
    private Utilities utilities;

    /** The rest client service. */
    @Autowired
    private RestClientService<Object> restClientService;

    /** The env. */
    @Autowired
    private Environment env;

    @Autowired
    private PublisherClient<String, Object, HttpHeaders> pb;

    @Value("#{'${mosip.mandatory-languages:}'.concat('${mosip.optional-languages:}')}")
    private String supportedLang;

    public boolean generateDocuments(EventModel eventModel) throws Exception {
        Path eventFilePath = Path.of(utilities.getDataPath(),
                String.format(EVENT_JSON_FILE_NAME, eventModel.getEvent().getTransactionId()));
        Files.write(eventFilePath, gson.toJson(eventModel).getBytes(), StandardOpenOption.CREATE);
        log.info("Event data saved:: " + eventFilePath.toFile().getAbsolutePath());

        Map<String, byte[]> byteMap = new HashMap<>();
        String decodedCredential = null;
        String credentialSubject = null;
        String credential = null;

        try {
            if (eventModel.getEvent().getDataShareUri() == null || eventModel.getEvent().getDataShareUri().isEmpty()) {
                credential = eventModel.getEvent().getData().get("credential").toString();
            } else {
                String dataShareUrl = eventModel.getEvent().getDataShareUri();
                URI dataShareUri = URI.create(dataShareUrl);
                credential = restApiClient.getApi(dataShareUri, String.class);
            }
            String encryptionPin = eventModel.getEvent().getData().get("protectionKey").toString();
            decodedCredential = cryptoCoreUtil.decrypt(credential);
            @SuppressWarnings("unchecked")
            Map<String, String> proofMap = (Map<String, String>) eventModel.getEvent().getData().get("proof");
            String sign = proofMap.get("signature").toString();

            credentialSubject = getCredentialSubject(decodedCredential);

            org.json.JSONObject credentialJSON = decrypt(decodedCredential, credentialSubject, encryptionPin);

            Path vcTextFilePath = Path.of(utilities.getDataPath(),
                    String.format(VC_JSON_FILE_NAME, eventModel.getEvent().getTransactionId()));
            Files.deleteIfExists(vcTextFilePath);
            Files.write(vcTextFilePath, gson.toJson(gson.fromJson(decodedCredential, TreeMap.class)).getBytes(), StandardOpenOption.CREATE);

            String credentialType = eventModel.getEvent().getData().get("credentialType").toString();
            byteMap = getDocuments(credentialJSON, credentialType, eventModel.getEvent().getTransactionId(), getSignature(sign, credential));

            Path textFilePath = Path.of(utilities.getDataPath(),
                    String.format(CARD_JSON_FILE_NAME, eventModel.getEvent().getTransactionId()));
            Files.deleteIfExists(textFilePath);
            Files.write(textFilePath, byteMap.get(UIN_TEXT_FILE), StandardOpenOption.CREATE);
            log.info("Generated files from event:: " + textFilePath.toFile().getAbsolutePath());
        } catch (Exception e){
            log.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public org.json.JSONObject decrypt(String credential, String credentialSubject, String encryptionPin) {
        org.json.JSONObject decryptedJson;
        LogDescription description = new LogDescription();
        try {
            decryptedJson = decryptAttribute(new org.json.JSONObject(credentialSubject), encryptionPin, credential);
        } catch (Exception e) {
            description.setMessage(PlatformErrorMessages.MIMOTO_VC_DECRYPTION_FAILED.getMessage());
            description.setCode(PlatformErrorMessages.MIMOTO_VC_DECRYPTION_FAILED.getCode());
            log.error(description.toString(), e);
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.VC_DECRYPTION_EXCEPTION.getErrorCode(),
                    e.getMessage() + ExceptionUtils.getStackTrace(e));
        }

        return decryptedJson;
    }

    public Map<String, byte[]> getDocuments(
            org.json.JSONObject credentialJSON,
            String credentialType,
            String requestId,
            String sign) {
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                "CredentialShareServiceImpl::getDocuments()::entry");

        Map<String, byte[]> byteMap = new HashMap<>();
        String id = null;
        LogDescription description = new LogDescription();
        String individualBio = null;
        boolean isTransactionSuccessful = false;
        try {
            individualBio = credentialJSON.getString("biometrics");
            String individualBiometric = individualBio;
            if (credentialJSON.has("UIN"))
                id = credentialJSON.getString("UIN");
            else if (credentialJSON.has(vid))
                id = credentialJSON.getString(vid);

            byte[] textFileByte = createJSONFile(credentialJSON, individualBiometric);
            byteMap.put(UIN_TEXT_FILE, textFileByte);

            // TODO: Uncomment this after datashare creation API fixed.
            // statusUpdate(requestId, textFileByte, credentialType);
            isTransactionSuccessful = true;

        } catch (Exception e) {
            description.setMessage(PlatformErrorMessages.MIMOTO_DOCUMENT_GENERATION_FAILED.getMessage());
            description.setCode(PlatformErrorMessages.MIMOTO_DOCUMENT_GENERATION_FAILED.getCode());
            log.error(description.toString(), e);
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorCode(),
                    e.getMessage() + ExceptionUtils.getStackTrace(e));

        } finally {
            String eventId = "";
            String eventName = "";
            String eventType = "";
            if (isTransactionSuccessful) {
                description.setMessage(PlatformSuccessMessages.RPR_MIMOTO_SERVICE_SUCCESS.getMessage());
                description.setCode(PlatformSuccessMessages.RPR_MIMOTO_SERVICE_SUCCESS.getCode());

                eventId = EventId.RPR_402.toString();
                eventName = EventName.UPDATE.toString();
                eventType = EventType.BUSINESS.toString();
            } else {
                description.setMessage(PlatformErrorMessages.MIMOTO_PDF_GENERATION_FAILED.getMessage());
                description.setCode(PlatformErrorMessages.MIMOTO_PDF_GENERATION_FAILED.getCode());

                eventId = EventId.RPR_405.toString();
                eventName = EventName.EXCEPTION.toString();
                eventType = EventType.SYSTEM.toString();
            }
            /** Module-Id can be Both Success/Error code */
            String moduleId = isTransactionSuccessful ? PlatformSuccessMessages.RPR_MIMOTO_SERVICE_SUCCESS.getCode()
                    : description.getCode();
            String moduleName = ModuleName.MIMOTO_SERVICE.toString();
            auditLogRequestBuilder.createAuditRequestBuilder(description.getMessage(), eventId, eventName, eventType,
                    moduleId, moduleName, id);
        }
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
                "CredentialShareServiceImpl::getDocuments()::exit");

        return byteMap;
    }

    @SuppressWarnings("unchecked")
    public byte[] createJSONFile(org.json.JSONObject credential, String individualBiometric) throws IOException {
        org.json.JSONObject outputJSON = new org.json.JSONObject();
        if (credential == null) {
            throw new IdentityNotFoundException(PlatformErrorMessages.MIMOTO_PIS_IDENTITY_NOT_FOUND.getMessage());
        }
        // Use local JSON template to include biometrics.
        JSONObject templateJSON = utilities.getTemplate();
        Set<String> templateKeys = templateJSON.keySet();
        for (String key : templateKeys) {
            String templateValue = (String) templateJSON.get(key);
            for (String value : templateValue.split(",")) {
                Object object = credential.has(value) ? credential.get(value) : null;
                if (object instanceof ArrayList) {
                    appendLangToOutputJSONFields(credential, outputJSON, value);
                } else if (object instanceof LinkedHashMap) {
                    org.json.JSONObject json = credential.getJSONObject(value);
                    outputJSON.put(value, json.get(VALUE));
                } else if (key.equals("biometrics")) {
                    outputJSON.put(value, getBiometricsDataJSON(individualBiometric));
                } else {
                    outputJSON.put(value, object);
                }
            }
        }
        return outputJSON.toString().getBytes();
    }

    /**
     * Decode biometrics data from CBEFF and return biometrics JSON object.
     *
     * @param individualBiometric
     * @return
     */
    public org.json.JSONObject getBiometricsDataJSON(String individualBiometric) {
        org.json.JSONObject biometrics = new org.json.JSONObject();
        if (individualBiometric != null) {
            try {
                List<BIR> bIRTypeList = util.getBIRTypeList(individualBiometric);
                for (int i = 0; i < bIRTypeList.size(); i++) {
                    BDBInfo bdbInfo = bIRTypeList.get(i).getBdbInfo();
                    String type = bdbInfo.getType().get(0).value().toLowerCase();
                    List<String> subType = bdbInfo.getSubtype();
                    byte[] photoBytes = util.getPhotoByTypeAndSubType(bIRTypeList, type, subType);
                    if (photoBytes != null) {
                        String data = getData(type, photoBytes);
                        if (subType.isEmpty()) {
                            addTypeToBiometricWithFormatPrefixAndData(biometrics, type, data);
                        } else {
                            addTypeToBiometricIfNotExists(biometrics, type, subType, data);
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Something wrong when trying to get biometrics data", e);
            }
        }

        return biometrics;
    }

    public String getSignature(String sign, String credential) {
        String signHeader = sign.split("\\.")[0];
        String signData = sign.split("\\.")[2];
        String signature = signHeader + "." + credential + "." + signData;
        return signature;
    }

    @SuppressWarnings("unused")
    private byte[] extractFaceImageData(byte[] decodedBioValue) {

        try (DataInputStream din = new DataInputStream(new ByteArrayInputStream(decodedBioValue))) {

            byte[] format = new byte[4];
            din.read(format, 0, 4);
            byte[] version = new byte[4];
            din.read(version, 0, 4);
            int recordLength = din.readInt();
            short numberofRepresentionRecord = din.readShort();
            byte certificationFlag = din.readByte();
            byte[] temporalSequence = new byte[2];
            din.read(temporalSequence, 0, 2);
            int representationLength = din.readInt();
            byte[] representationData = new byte[representationLength - 4];
            din.read(representationData, 0, representationData.length);
            try (DataInputStream rdin = new DataInputStream(new ByteArrayInputStream(representationData))) {
                byte[] captureDetails = new byte[14];
                rdin.read(captureDetails, 0, 14);
                byte noOfQualityBlocks = rdin.readByte();
                if (noOfQualityBlocks > 0) {
                    byte[] qualityBlocks = new byte[noOfQualityBlocks * 5];
                    rdin.read(qualityBlocks, 0, qualityBlocks.length);
                }
                short noOfLandmarkPoints = rdin.readShort();
                byte[] facialInformation = new byte[15];
                rdin.read(facialInformation, 0, 15);
                if (noOfLandmarkPoints > 0) {
                    byte[] landmarkPoints = new byte[noOfLandmarkPoints * 8];
                    rdin.read(landmarkPoints, 0, landmarkPoints.length);
                }
                byte faceType = rdin.readByte();
                byte imageDataType = rdin.readByte();
                byte[] otherImageInformation = new byte[9];
                rdin.read(otherImageInformation, 0, otherImageInformation.length);
                int lengthOfImageData = rdin.readInt();

                byte[] image = new byte[lengthOfImageData];
                rdin.read(image, 0, lengthOfImageData);

                return image;
            }
        } catch (Exception ex) {
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorCode(),
                    ex.getMessage() + ExceptionUtils.getStackTrace(ex));
        }
    }

    public String getCredentialSubject(String credential) {
        org.json.JSONObject jsonObject = new org.json.JSONObject(credential);
            String credentialSubject = jsonObject.get("credentialSubject").toString();
        return credentialSubject;
    }

    /**
     * Decrypt protected (encrypted) attributes.
     *
     * @param data
     * @param encryptionPin
     * @param credential
     * @return
     * @throws ParseException
     */
    public org.json.JSONObject decryptAttribute(org.json.JSONObject data, String encryptionPin, String credential)
            throws ParseException {

        JSONParser parser = new JSONParser(); // this needs the "json-simple" library
        Object obj = parser.parse(credential);
        JSONObject jsonObj = (org.json.simple.JSONObject) obj;

        JSONArray jsonArray = (JSONArray) jsonObj.get("protectedAttributes");
        if (jsonArray != null) {
            for (Object str : jsonArray) {

                CryptoWithPinRequestDto cryptoWithPinRequestDto = new CryptoWithPinRequestDto();
                CryptoWithPinResponseDto cryptoWithPinResponseDto = new CryptoWithPinResponseDto();

                cryptoWithPinRequestDto.setUserPin(encryptionPin);
                cryptoWithPinRequestDto.setData(data.getString(str.toString()));
                try {
                    cryptoWithPinResponseDto = cryptoUtil.decryptWithPin(cryptoWithPinRequestDto);
                } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                         | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                    log.error("Error while decrypting the data", e);
                    throw new CryptoManagerException(PlatformErrorMessages.MIMOTO_INVALID_KEY_EXCEPTION.getCode(),
                            PlatformErrorMessages.MIMOTO_INVALID_KEY_EXCEPTION.getMessage(), e);
                }
                data.put((String) str, cryptoWithPinResponseDto.getData());

            }
        }

        return data;
    }

    private void appendLangToOutputJSONFields(org.json.JSONObject credential, org.json.JSONObject outputJSON, String value) {
        JSONArray node = new JSONArray();
        node.addAll(credential.getJSONArray(value).toList());
        JsonValue[] jsonValues = mapJsonNodeToJavaObject(JsonValue.class, node);
        for (JsonValue jsonValue : jsonValues) {
            if (supportedLang.contains(jsonValue.getLanguage())) {
                outputJSON.put(value + "_" + jsonValue.getLanguage(), jsonValue);
            }
        }
    }

    /**
     * Map json node to java object.
     * Maps JSONArray elements to Java objects by setting language and value fields.
     *
     * @param <T> the generic type
     * @param genericType the generic type
     * @param demographicJsonNode the demographic json node
     * @return the array of mapped objects
     */
    @SuppressWarnings("unchecked")
    private <T> T[] mapJsonNodeToJavaObject(Class<? extends Object> genericType, JSONArray demographicJsonNode) {
        String language;
        String value;
        T[] javaObject = (T[]) java.lang.reflect.Array.newInstance(genericType, demographicJsonNode.size());
        try {
            for (int i = 0; i < demographicJsonNode.size(); i++) {
                T jsonNodeElement = (T) genericType.getDeclaredConstructor().newInstance();
                JSONObject objects = getJSONObjectFromArray(demographicJsonNode, i);
                if (objects != null) {
                    language = (String) objects.get("language");
                    value = (String) objects.get("value");
                    FieldUtils.writeField(jsonNodeElement, "language", language, true);
                    FieldUtils.writeField(jsonNodeElement, "value", value, true);
                    javaObject[i] = jsonNodeElement;
                }
            }
        } catch (InstantiationException | IllegalAccessException | java.lang.reflect.InvocationTargetException | NoSuchMethodException e) {
            throw new InstantanceCreationException(PlatformErrorMessages.MIMOTO_SYS_INSTANTIATION_EXCEPTION.getMessage(), e);
        } catch (SecurityException e) {
            throw new FieldNotFoundException(PlatformErrorMessages.MIMOTO_SYS_NO_SUCH_FIELD_EXCEPTION.getMessage(), e);
        }
        return javaObject;
    }

    /**
     * Iterates the JSONArray and returns JSONObject for given index.
     *
     * @param jsonArray the json array
     * @param index the index
     * @return the JSON object
     */
    @SuppressWarnings("unchecked")
    private JSONObject getJSONObjectFromArray(JSONArray jsonArray, int index) {
        Object object = jsonArray.get(index);
        if (object instanceof LinkedHashMap) {
            LinkedHashMap<String, Object> identity = (LinkedHashMap<String, Object>) jsonArray.get(index);
            return identity != null ? new JSONObject(identity) : null;
        } else {
            return (JSONObject) object;
        }
    }

    private String getData(String type, byte[] photoBytes) {
        if (type.equalsIgnoreCase(BiometricType.FACE.value())) {
            // Convert face image from JPEG2000 to JPG and encode with base64.
            // Assume that the face image is in JPEG2000 format.
            return Base64.getEncoder().encodeToString(CommonUtil.convertJP2ToJPEGBytes(extractFaceImageData(photoBytes)));
        } else {
            return Base64.getEncoder().encodeToString(photoBytes);
        }
    }

    private static void addTypeToBiometricWithFormatPrefixAndData(org.json.JSONObject biometrics, String type, String data) {
        String formatPrefix = type.equalsIgnoreCase(BiometricType.FACE.value()) ? DATA_IMAGE_JPG_BASE_64 : DATA_BINARY_BASE_64;
        biometrics.put(type, formatPrefix + data);
    }

    private static void addTypeToBiometricIfNotExists(org.json.JSONObject biometrics, String type, List<String> subType, String data) {
        org.json.JSONObject typeList = biometrics.has(type) ? biometrics.getJSONObject(type)
                : new org.json.JSONObject();
        typeList.put(String.join("_", subType).toLowerCase(), DATA_BINARY_BASE_64 + data);
        if (!biometrics.has(type)) {
            biometrics.put(type, typeList);
        }
    }
}
