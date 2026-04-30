package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.ExceptionUtils;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static io.mosip.mimoto.constant.LoggerFileConstant.DELIMITER;

@Component
@Slf4j
@Data
public class Utilities {
    private static final Logger log = LoggerFactory.getLogger(Utilities.class);

    private ClassLoader classLoader = Utilities.class.getClassLoader();

    public ObjectMapper objectMapper = new ObjectMapper();

    @Value("${credential.template}")
    private String defaultTemplate;

    @Value("${credential.data.path}")
    private String dataPath;

    // Sample decrypted VC
    private String SAMPLE_VCD = "%s_VCD.json";

    // Sample VC websub event
    private String SAMPLE_EVENT = "%s_EVENT.json";

    @Autowired
    private RestApiClient restApiClient;

    /**
     * The config server file storage URL.
     */
    @Value("${config.server.file.storage.uri}")
    private String configServerFileStorageURL;

    /**
     * The get reg issuers config json.
     */
    @Value("${mosip.openid.issuers}")
    private String issuersConfigPath;

    @Value("${mosip.openid.verifiers}")
    private String trustedVerifiersPath;

    @Value("${mosip.openid.htmlTemplate}")
    private String credentialTemplatePath;

    private String issuersConfigJsonString = null;

    private String trustedVerifiersJsonString = null;

    private String credentialTemplateHtmlString = null;

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @PostConstruct
    public void setUp() throws IOException {
        if(activeProfile.contains("local")) {
            Resource resource = new ClassPathResource(issuersConfigPath);
            Resource trustedVerifiersResource = new ClassPathResource(trustedVerifiersPath);
            Resource credentialTemplateResource = new ClassPathResource("templates/"+ credentialTemplatePath);

            trustedVerifiersJsonString = (Files.readString(trustedVerifiersResource.getFile().toPath()));
            issuersConfigJsonString = (Files.readString(resource.getFile().toPath()));
            credentialTemplateHtmlString = (Files.readString(credentialTemplateResource.getFile().toPath()));
        }
    }

    public static String encodeToString(BufferedImage image, String type) {
        String imageString = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            ImageIO.write(image, type, bos);
            byte[] imageBytes = bos.toByteArray();
            Base64.Encoder encoder = Base64.getEncoder();
            imageString = encoder.encodeToString(imageBytes);
            bos.close();
        } catch (Exception e) {
            log.error(ExceptionUtils.getStackTrace(e));
        }
        return imageString;
    }

    public JSONObject getTemplate() throws IOException {
        return objectMapper.readValue(classLoader.getResourceAsStream(defaultTemplate), JSONObject.class);
    }

    public JsonNode getVC(String requestId) throws IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_JSON_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public JsonNode getRequestVC(String requestId) throws IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public JsonNode getDecryptedVC(String requestId) throws IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.CARD_JSON_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public void removeCacheData(String requestId) throws IOException {
        List<Path> filePathList = new ArrayList<Path>();
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.EVENT_JSON_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_JSON_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.CARD_JSON_FILE_NAME, requestId)));
        for (Path filePath : filePathList) {
            if (Files.exists(filePath)) {
                try {
                    Files.delete(filePath);
                } catch (Exception e) {
                    log.error("Cannot delete file: " + filePath, e);
                }
            }
        }
    }

    /**
     * Gets the json.
     *
     * @param configString the stringified config
     * @param resourcePath path of the resource
     * @return the json
     */
    public String getJson(String configString, String resourcePath) {
        String json = configString;
        try {
            if(StringUtils.isEmpty(json)){
                json = restApiClient.getApi(URI.create(configServerFileStorageURL + resourcePath), String.class);
            }
        } catch (Exception e) {
            log.error(ExceptionUtils.getStackTrace(e));
        }
        return json;
    }

    public String getIssuersConfigJsonValue() {
        return getJson(issuersConfigJsonString, issuersConfigPath);
    }
    public String getTrustedVerifiersJsonValue() {
        return getJson(trustedVerifiersJsonString, trustedVerifiersPath);
    }
    public String getCredentialSupportedTemplateString(String issuerId, String credentialConfigurationId) {
        String templateFileName = String.format("%s-%s-template.html", issuerId, credentialConfigurationId);
        if(activeProfile.contains("local")) {
            Path basePath = Paths.get("templates").toAbsolutePath().normalize();
            Path resolvedPath = basePath.resolve(templateFileName).normalize();

            if (!resolvedPath.startsWith(basePath)) {
                throw new SecurityException("Attempted path traversal attack: " + resolvedPath);
            }

            Resource credentialTemplateResource = new ClassPathResource(resolvedPath.toString());
            try {
                return Files.readString(credentialTemplateResource.getFile().toPath());
            } catch (IOException e) {
                log.error(ExceptionUtils.getStackTrace(e));
            }
            return credentialTemplateHtmlString;
        }
        String specificCredentialPDFTemplate = getJson("", templateFileName);
        return !StringUtils.isEmpty(specificCredentialPDFTemplate)? specificCredentialPDFTemplate : getJson("", credentialTemplatePath);
    }

    public static String[] handleExceptionWithErrorCode(Exception exception, String flowErrorCode) {
        String errorMessage = exception.getMessage();
        String errorCode = flowErrorCode;

        if (errorMessage.contains(DELIMITER)) {
            String[] errorSections = errorMessage.split(DELIMITER);
            errorCode = errorSections[0];
            errorMessage = errorSections[1];
        }
        return new String[]{errorCode, errorMessage};
    }
    public static <T> ResponseEntity<ResponseWrapper<T>> handleErrorResponse(
            Exception exception, String flowErrorCode, HttpStatus status, MediaType contentType) {
        String errorMessage = exception.getMessage();
        String errorCode = flowErrorCode;

        if (errorMessage.contains(DELIMITER)) {
            String[] errorSections = errorMessage.split(DELIMITER);
            errorCode = errorSections[0];
            errorMessage = errorSections[1];
        }

        ResponseWrapper<T> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setResponse(null);
        responseWrapper.setErrors(Utilities.getErrors(errorCode, errorMessage));
        ResponseEntity.BodyBuilder responseEntity = ResponseEntity.status(status);
        if (contentType != null) {
            responseEntity.contentType(contentType);
        }
        return responseEntity.body(responseWrapper);
    }

    public static <T> ResponseEntity<T> getErrorResponseEntityWithoutWrapper(
            Exception exception, String flowErrorCode, HttpStatus status, MediaType contentType) {
        String errorMessage = exception.getMessage();
        String errorCode = flowErrorCode;

        if (errorMessage.contains(DELIMITER)) {
            String[] errorSections = errorMessage.split(DELIMITER);
            errorCode = errorSections[0];
            errorMessage = errorSections[1];
        }

        ResponseEntity.BodyBuilder responseEntity = ResponseEntity.status(status);
        if (contentType != null) {
            responseEntity.contentType(contentType);
        }
        return (ResponseEntity<T>) responseEntity.body(new ErrorDTO(errorCode, errorMessage));
    }

    public static <T> ResponseEntity<T> getErrorResponseEntityFromPlatformErrorMessage(
            ErrorConstants message, HttpStatus status, MediaType contentType) {
        String errorMessage = message.getErrorMessage();
        String errorCode = message.getErrorCode();

        ResponseEntity.BodyBuilder responseEntity = ResponseEntity.status(status);
        if (contentType != null) {
            responseEntity.contentType(contentType);
        }
        return (ResponseEntity<T>) responseEntity.body(new ErrorDTO(errorCode, errorMessage));
    }

    public static ResponseEntity<ErrorDTO> buildErrorResponse(HttpStatus status, String errorCode, String message) {
        return ResponseEntity
                .status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ErrorDTO(errorCode, message));
    }

    public static List<ErrorDTO> getErrors(String errorCode, String errorMessage) {
        ErrorDTO errorDTO = new ErrorDTO(errorCode, errorMessage);
        return Lists.newArrayList(errorDTO);
    }

    public static String maskValue(String value) {
        if (StringUtils.isEmpty(value)) {
            return value;
        }
        // mask of length 20 or less
        return "X".repeat(Math.min(value.length(), 20));
    }

    public String getDataPath() {
        return dataPath;
    }
}
