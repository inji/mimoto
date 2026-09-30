package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.DataShareResponseDto;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static io.mosip.mimoto.util.TestUtilities.getDataShareResponseDTO;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class DataShareServiceTest {

    @Mock
    RestApiClient restApiClient;
    @Mock
    ObjectMapper objectMapper;

    DataShareServiceImpl dataShareService;
    PresentationRequestDTO presentationRequestDTO;

    private static final String TEST_CREATE_URL = "https://test-url";
    private static final String TEST_GET_URL_PATTERN = "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*";
    private static final String MISCONFIGURED_GET_URL_PATTERN = "http://datashare.datashare/*";
    private static final int DEFAULT_MAX_RETRY_COUNT = 1;

    @BeforeEach
    public void setUp() {
        presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        dataShareService = new DataShareServiceImpl(
                restApiClient,
                objectMapper,
                TEST_CREATE_URL,
                TEST_GET_URL_PATTERN,
                DEFAULT_MAX_RETRY_COUNT
        );
    }

    @Test
    public void storeDataInDataShareWhenProperDataIsPassed() throws Exception {
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = TestUtilities.getDataShareResponseWrapperDTO();
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenReturn(dataShareResponseWrapperDTO);
        String actualDataShareLink = dataShareService.storeDataInDataShare("SampleData", "3");
        String expectedDataShareLink = dataShareResponseWrapperDTO.getDataShare().getUrl();
        assertEquals(expectedDataShareLink, actualDataShareLink);
    }

    @Test
    public void throwRequestTimedOutExceptionWhenMaxCountIsReached() throws Exception {
        dataShareService = new DataShareServiceImpl(restApiClient, objectMapper, TEST_CREATE_URL, TEST_GET_URL_PATTERN, 0);
        assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.storeDataInDataShare("SampleData", "3"));
    }

    @Test
    public void throwServiceUnavailableExceptionWhenCredentialPushIsNotDone() throws Exception {
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenThrow(InvalidCredentialResourceException.class);
        assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.storeDataInDataShare("SampleData", "3"));
    }

    @Test
    public void downloadCredentialWhenRequestIsProper() throws Exception {
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        String credentialString = TestUtilities.getObjectAsString(vcCredentialResponseDTO);
        Mockito.when(restApiClient.getApiWithCustomHeaders(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"), Mockito.eq(String.class), Mockito.any(HttpHeaders.class)))
                .thenReturn(credentialString);
        Mockito.when(objectMapper.readValue(credentialString, VCCredentialResponse.class))
                .thenReturn(vcCredentialResponseDTO);

        VCCredentialResponse actualVCCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);

        assertEquals(vcCredentialResponseDTO, actualVCCredentialResponse);
    }

    @Test
    public void throwInvalidResourceExceptionWhenResourceURLDoesNotMatchPattern() {
        presentationRequestDTO.setResource("test-resource");
        String expectedExceptionMsg = "invalid_resource --> The requested resource is invalid.";

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwInvalidResourceExceptionOnDownloadingCredentialFromDataShareFailure() {
        Mockito.when(restApiClient.getApiWithCustomHeaders(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"), Mockito.eq(String.class), Mockito.any(HttpHeaders.class)))
                .thenReturn(null);
        String expectedExceptionMsg = "server_unavailable --> The server is not reachable right now.";

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceExpiredExceptionWhenCredentialIsExpired() throws JsonProcessingException {
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        vcCredentialResponseDTO.setCredential(null);
        String credentialString = TestUtilities.getObjectAsString(vcCredentialResponseDTO);
        Mockito.when(restApiClient.getApiWithCustomHeaders(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"), Mockito.eq(String.class), Mockito.any(HttpHeaders.class)))
                .thenReturn(credentialString);
        Mockito.when(objectMapper.readValue(credentialString, VCCredentialResponse.class)).thenReturn(vcCredentialResponseDTO);
        Mockito.when(objectMapper.readValue(credentialString, DataShareResponseDto.class)).thenReturn(getDataShareResponseDTO(""));
        String expectedExceptionMsg = "resource_not_found --> The requested resource expired.";

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceNotFoundExceptionWhenCredentialIsNotFoundInDataShare() throws JsonProcessingException {
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        vcCredentialResponseDTO.setCredential(null);
        String credentialString = TestUtilities.getObjectAsString(vcCredentialResponseDTO);
        Mockito.when(restApiClient.getApiWithCustomHeaders(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"), Mockito.eq(String.class), Mockito.any(HttpHeaders.class)))
                .thenReturn(credentialString);
        Mockito.when(objectMapper.readValue(credentialString, VCCredentialResponse.class)).thenReturn(vcCredentialResponseDTO);
        Mockito.when(objectMapper.readValue(credentialString, DataShareResponseDto.class)).thenReturn(getDataShareResponseDTO("DAT-SER-008"));
        String expectedExceptionMsg = "resource_not_found --> The requested resource doesn’t exist.";

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLIsMisconfiguredAndHasNoWildcard() {
        String expectedExceptionMsg = "invalid_resource --> Invalid resource identifier in URL";
        dataShareService = new DataShareServiceImpl(restApiClient, objectMapper, TEST_CREATE_URL, MISCONFIGURED_GET_URL_PATTERN, DEFAULT_MAX_RETRY_COUNT);

        presentationRequestDTO.setResource("http://datashare.datashare/");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @ParameterizedTest
    @CsvSource({
        "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/te..st,    invalid_resource --> Invalid path structure in resource URL",
        "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid//test,     invalid_resource --> Invalid path structure in resource URL",
        "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test$,     invalid_resource --> Invalid characters in wildcard segment",
        "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/%%illegal, invalid_resource --> Malformed resource URL",
        "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/%252e%252e,invalid_resource --> Invalid characters in wildcard segment"
    })
    public void throwResourceInvalidRequestExceptionForInvalidCredentialURL(String resourceUrl, String expectedExceptionMsg) {
        presentationRequestDTO.setResource(resourceUrl);

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class,
                () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg.strip(), actualException.getMessage());
    }
}
