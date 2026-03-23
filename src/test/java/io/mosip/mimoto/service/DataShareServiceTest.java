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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import static io.mosip.mimoto.util.TestUtilities.getDataShareResponseDTO;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@RunWith(MockitoJUnitRunner.class)

public class DataShareServiceTest {

    @Mock
    RestApiClient restApiClient;
    @Mock
    ObjectMapper objectMapper;

    DataShareServiceImpl dataShareService;
    PresentationRequestDTO presentationRequestDTO;

    @Before
    public void setUp() {
        presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        dataShareService = new DataShareServiceImpl(
                restApiClient,
                objectMapper,
                "https://test-url",
                "https://test-url",
                "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*",
                1
        );
    }

    @Test
    public void storeDataInDataShareWhenProperDataIsPassed() throws Exception {
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = TestUtilities.getDataShareResponseWrapperDTO();
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenReturn(dataShareResponseWrapperDTO);
        String actualDataShareLink = dataShareService.storeDataInDataShare("SampleData", "3");
        String expectedDataShareLink = dataShareResponseWrapperDTO.getDataShare().getUrl();
        Assert.assertEquals(expectedDataShareLink, actualDataShareLink);
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwRequestTimedOutExceptionWhenMaxCountIsReached() throws Exception {
        dataShareService = new DataShareServiceImpl(restApiClient, objectMapper, "https://test-url", "https://test-url", "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*", 0);
        dataShareService.storeDataInDataShare("SampleData", "3");
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwServiceUnavailableExceptionWhenCredentialPushIsNotDone() throws Exception {
        dataShareService = new DataShareServiceImpl(restApiClient, objectMapper, "https://test-url", "https://test-url", "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*", 1);
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenThrow(InvalidCredentialResourceException.class);
        dataShareService.storeDataInDataShare("SampleData", "3");
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

        Assert.assertEquals(vcCredentialResponseDTO, actualVCCredentialResponse);
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
    public void throwResourceInvalidRequestExceptionWhenCredentialURLHasIllegalDirectoryCharacter() {
        String expectedExceptionMsg = "invalid_resource --> Invalid path structure in resource URL";

        presentationRequestDTO.setResource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/te..st");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLHasIllegalForwardSlashCharacter() {
        String expectedExceptionMsg = "invalid_resource --> Invalid path structure in resource URL";

        presentationRequestDTO.setResource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid//test");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLIsMisconfiguredAndHasNoWildcard() {
        String expectedExceptionMsg = "invalid_resource --> Invalid resource identifier in URL";
        dataShareService = new DataShareServiceImpl(restApiClient, objectMapper, "https://test-url", "https://test-url", "http://datashare.datashare/*", 1);

        presentationRequestDTO.setResource("http://datashare.datashare/");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLHasIllegalCharacters() {
        String expectedExceptionMsg = "invalid_resource --> Invalid characters in wildcard segment";
        presentationRequestDTO.setResource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test$");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLIsMalformed() {
        String expectedExceptionMsg = "invalid_resource --> Malformed resource URL";
        presentationRequestDTO.setResource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/%%illegal");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class, () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void throwResourceInvalidRequestExceptionWhenCredentialURLHasDoubleEncodedPathTraversal() {
        String expectedExceptionMsg = "invalid_resource --> Invalid characters in wildcard segment";
        presentationRequestDTO.setResource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/%252e%252e");

        InvalidCredentialResourceException actualException = assertThrows(InvalidCredentialResourceException.class,
                () -> dataShareService.downloadCredentialFromDataShare(presentationRequestDTO));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }
}
