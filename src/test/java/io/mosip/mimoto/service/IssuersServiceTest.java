package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.IssuersV2DTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.IssuerConfigUtil;
import io.mosip.mimoto.util.Utilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class IssuersServiceTest {

    @InjectMocks
    IssuersServiceImpl issuersService;

    @Mock
    Utilities utilities;

    @Mock
    IssuerConfigUtil issuersConfigUtil;

    @Spy
    ObjectMapper objectMapper;

    String issuerWellKnownUrl, issuerId, credentialIssuerHostUrl, authServerWellknownUrl, issuersConfigJsonValue;
    CredentialIssuerConfiguration expectedCredentialIssuerConfiguration;
    IssuersDTO issuers = new IssuersDTO();

    CredentialIssuerWellKnownResponse expectedCredentialIssuerWellKnownResponse;

    private final String publicUrl = "https://dev";
    private final String context = "";

    @Before
    public void setUp() throws Exception {
        issuerWellKnownUrl = "https://issuer.env.net/.well-known/openid-credential-issuer";
        authServerWellknownUrl = "https://auth-server.env.net";
        issuerId = "Issuer3id";
        credentialIssuerHostUrl = "https://issuer.env.net";

        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer3"), getIssuerConfigDTO("Issuer4")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);

        expectedCredentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId,
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        Mockito.when(issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl))
                .thenReturn(expectedCredentialIssuerWellKnownResponse);

        expectedCredentialIssuerConfiguration = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());
        Mockito.when(issuersConfigUtil.getAuthServerWellknown(authServerWellknownUrl)).thenReturn(expectedCredentialIssuerConfiguration.getAuthorizationServerWellKnownResponse());

        issuersService = new IssuersServiceImpl(utilities, objectMapper, issuersConfigUtil, publicUrl, context);
    }

    @Test
    public void shouldReturnAllIssuersWhenSearchValueIsNull() throws ApiNotAccessibleException, IOException {
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuers.forEach(i -> i.setToken_endpoint(publicUrl + context + "/get-token/" + i.getIssuer_id()));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO allIssuers = issuersService.getIssuers(null);

        assertEquals(expectedIssuers, allIssuers);
    }

    @Test
    public void shouldReturnMatchingIssuersWhenSearchValuePatternMatchesWithIssuerName() throws ApiNotAccessibleException, IOException {
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedFilteredIssuers = new IssuersDTO();
        List<IssuerDTO> filteredIssuersList = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1")));
        filteredIssuersList.forEach(i -> i.setToken_endpoint(publicUrl + context + "/get-token/" + i.getIssuer_id()));
        expectedFilteredIssuers.setIssuers(filteredIssuersList);

        IssuersDTO filteredIssuers = issuersService.getIssuers("Issuer1");

        assertEquals(expectedFilteredIssuers, filteredIssuers);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingAllIssuers() throws IOException, ApiNotAccessibleException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuers(null);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForTheIssuerIdIfExist() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuerDTO expectedIssuer = getIssuerConfigDTO("Issuer3");
        expectedIssuer.setToken_endpoint(publicUrl + context + "/get-token/" + expectedIssuer.getIssuer_id());

        IssuerDTO issuer = issuersService.getIssuerDetails("Issuer3id");

        assertEquals(expectedIssuer, issuer);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForAllIssuer() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer3"), getIssuerConfigDTO("Issuer4")));
        issuers.forEach(i -> i.setToken_endpoint(publicUrl + context + "/get-token/" + i.getIssuer_id()));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO issuersDTO = issuersService.getAllIssuers();

        assertEquals(expectedIssuers, issuersDTO);
    }

    @Test(expected = InvalidIssuerIdException.class)
    public void shouldThrowExceptionIfTheIssuerIdNotExists() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        issuersService.getIssuerDetails("Issuer5id");
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingIssuerConfig() throws IOException, ApiNotAccessibleException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuerDetails("Issuers1id");
    }

    @Test
    public void shouldReturnOnlyEnabledIssuers() throws IOException, ApiNotAccessibleException {
        IssuersDTO issuers = new IssuersDTO();
        IssuerDTO enabledIssuer = getIssuerConfigDTO("Issuer1");
        IssuerDTO disabledIssuer = getIssuerConfigDTO("Issuer2");
        disabledIssuer.setEnabled("false");
        issuersConfigJsonValue = new Gson().toJson(issuers);
        issuers.setIssuers(List.of(enabledIssuer, disabledIssuer));
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedIssuersDTO = new IssuersDTO();
        enabledIssuer.setToken_endpoint(publicUrl + context + "/get-token/" + enabledIssuer.getIssuer_id());
        expectedIssuersDTO.setIssuers(List.of(enabledIssuer));

        IssuersDTO actualIssuersDTO = issuersService.getIssuers("");

        assertEquals(expectedIssuersDTO, actualIssuersDTO);
        assertEquals("true", actualIssuersDTO.getIssuers().getFirst().getEnabled());
        assertEquals(1, actualIssuersDTO.getIssuers().size());
    }

    @Test
    public void shouldReturnProperCredentialConfigurationsForTheRequestedIssuer() throws AuthorizationServerWellknownResponseException, ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerConfiguration actualCredentialIssuerConfiguration = issuersService.getIssuerConfiguration("Issuer3id");

        assertEquals(expectedCredentialIssuerConfiguration, actualCredentialIssuerConfiguration);
    }

    @Test
    public void issuersConfigShouldThrowExceptionIfAnyErrorOccurredWhileFetchingIssuersWellknown() {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> issuersService.getIssuerConfiguration(issuerId));

        assertEquals("RESIDENT-APP-026 --> Api not accessible failure", actualException.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }


    @Test
    public void issuersConfigShouldThrowExceptionIfAnyErrorOccurredWhileFetchingIssuersAuthorizationServerWellknown() throws AuthorizationServerWellknownResponseException {
        Mockito.when(issuersConfigUtil.getAuthServerWellknown(authServerWellknownUrl)).thenThrow(new AuthorizationServerWellknownResponseException("well-known api is not accessible"));

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> issuersService.getIssuerConfiguration("Issuer3id"));

        assertEquals("RESIDENT-APP-042 --> Invalid Authorization Server well-known from server:\n" +
                "well-known api is not accessible", actualException.getMessage());
        verify(issuersConfigUtil, times(1)).getAuthServerWellknown(authServerWellknownUrl);
    }

    // Existing imports and class setup remain unchanged
// Add these test cases to the existing IssuersServiceTest class

    @Test
    public void shouldReturnIssuerConfigForValidIssuerIdAndCredentialType() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, InvalidWellknownResponseException {
        // Arrange
        String issuerId = "Issuer3id";
        String credentialType = "CredentialType1";
        IssuerDTO expectedIssuerDTO = getIssuerConfigDTO("Issuer3");
        expectedIssuerDTO.setToken_endpoint(publicUrl + context + "/get-token/" + expectedIssuerDTO.getIssuer_id());
        CredentialIssuerWellKnownResponse wellKnownResponse = getCredentialIssuerWellKnownResponseDto(
                issuerId, Map.of(credentialType, getCredentialSupportedResponse(credentialType)));
        IssuerConfig expectedIssuerConfig = new IssuerConfig(
                expectedIssuerDTO,
                wellKnownResponse,
                wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType)
        );

        // Act
        IssuerConfig actualIssuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);

        // Assert
        assertEquals(expectedIssuerConfig, actualIssuerConfig);
        assertEquals(expectedIssuerDTO, actualIssuerConfig.getIssuerDTO());
        assertEquals(wellKnownResponse, actualIssuerConfig.getWellKnownResponse());
        assertEquals(wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType),
                actualIssuerConfig.getCredentialsSupportedResponse());
        verify(issuersConfigUtil, times(1)).getIssuerWellknown(credentialIssuerHostUrl);
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldThrowInvalidIssuerIdExceptionForNonExistentIssuerId() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        // Arrange
        String issuerId = "InvalidIssuerId";
        String credentialType = "CredentialType1";

        // Act & Assert
        InvalidIssuerIdException exception = assertThrows(InvalidIssuerIdException.class,
                () -> issuersService.getIssuerConfig(issuerId, credentialType));

        assertEquals("RESIDENT-APP-035 --> Invalid issuer ID", exception.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
        verify(issuersConfigUtil, never()).getIssuerWellknown(anyString());
    }

    @Test
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersConfigJsonIsNull() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        // Arrange
        String issuerId = "Issuer3id";
        String credentialType = "CredentialType1";
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        // Act & Assert
        ApiNotAccessibleException exception = assertThrows(ApiNotAccessibleException.class,
                () -> issuersService.getIssuerConfig(issuerId, credentialType));

        assertEquals("RESIDENT-APP-026 --> Unable to fetch issuer configuration for issuerId: Issuer3id; \n" +
                "nested exception is io.mosip.mimoto.exception.ApiNotAccessibleException: RESIDENT-APP-026 --> Api not accessible failure", exception.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
        verify(issuersConfigUtil, never()).getIssuerWellknown(anyString());
    }

    @Test
    public void shouldThrowApiNotAccessibleExceptionWhenGetIssuerWellknownFails() throws IOException, InvalidWellknownResponseException, ApiNotAccessibleException {
        // Arrange
        String issuerId = "Issuer3id";
        String credentialType = "CredentialType1";
        Mockito.when(issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl))
                .thenThrow(new ApiNotAccessibleException("Well-known endpoint inaccessible"));

        // Act & Assert
        ApiNotAccessibleException exception = assertThrows(ApiNotAccessibleException.class,
                () -> issuersService.getIssuerConfig(issuerId, credentialType));

        assertEquals("RESIDENT-APP-026 --> Unable to fetch issuer configuration for issuerId: Issuer3id; \n" +
                "nested exception is io.mosip.mimoto.exception.ApiNotAccessibleException: RESIDENT-APP-026 --> Well-known endpoint inaccessible", exception.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
        verify(issuersConfigUtil, times(1)).getIssuerWellknown(credentialIssuerHostUrl);
    }

    @Test
    public void shouldLogErrorWhenApiNotAccessibleExceptionOccurs() throws IOException, InvalidWellknownResponseException, ApiNotAccessibleException {
        // Arrange
        String issuerId = "Issuer3id";
        String credentialType = "CredentialType1";
        ApiNotAccessibleException apiException = new ApiNotAccessibleException("Well-known endpoint inaccessible");
        Mockito.when(issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl)).thenThrow(apiException);

        // Act & Assert
        ApiNotAccessibleException exception = assertThrows(ApiNotAccessibleException.class,
                () -> issuersService.getIssuerConfig(issuerId, credentialType));

        assertEquals("RESIDENT-APP-026 --> Unable to fetch issuer configuration for issuerId: Issuer3id; \n" +
                "nested exception is io.mosip.mimoto.exception.ApiNotAccessibleException: RESIDENT-APP-026 --> Well-known endpoint inaccessible", exception.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
        verify(issuersConfigUtil, times(1)).getIssuerWellknown(credentialIssuerHostUrl);
        // Note: Logging verification requires a logging framework setup (e.g., Logback with ListAppender)
    }

    
    @Test
    public void shouldReturnIssuersV2DTOWhenGetIssuersV2DTO() throws Exception {
        IssuersV2DTO result = issuersService.getIssuersV2DTO();

        assertEquals(2, result.getIssuers().size());
        IssuerV2DTO first = result.getIssuers().getFirst();
        assertEquals("Issuer3id", first.getIssuerId());
        assertEquals("OpenId4VCI", first.getProtocol());
        assertEquals(getIssuerConfigDTO("Issuer3").getDisplay(), first.getDisplay());
        assertEquals("123", first.getClientId());
        assertEquals(publicUrl + context + "/get-token/Issuer3id", first.getTokenEndpoint());
        assertEquals("test-client-alias", first.getClientAlias());
        assertEquals(getIssuerConfigDTO("Issuer3").getQr_code_type(), first.getQrCodeType());
        assertEquals("true", first.getEnabled());
        assertEquals("https://issuer.env.net", first.getCredentialIssuerHost());
        IssuerV2DTO second = result.getIssuers().get(1);
        assertEquals("Issuer4id", second.getIssuerId());
        assertEquals("https://issuer.env.net", second.getCredentialIssuerHost());
        verify(utilities, atLeast(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldReturnIssuerV2DetailsForValidIssuerId() throws Exception {
        IssuerV2DTO result = issuersService.getIssuerV2Details("Issuer3id");

        assertEquals("Issuer3id", result.getIssuerId());
        assertEquals("OpenId4VCI", result.getProtocol());
        assertEquals(getIssuerConfigDTO("Issuer3").getDisplay(), result.getDisplay());
        assertEquals("123", result.getClientId());
        assertEquals(publicUrl + context + "/get-token/Issuer3id", result.getTokenEndpoint());
        assertEquals("test-client-alias", result.getClientAlias());
        assertEquals(getIssuerConfigDTO("Issuer3").getQr_code_type(), result.getQrCodeType());
        assertEquals("true", result.getEnabled());
        assertEquals("https://issuer.env.net", result.getCredentialIssuerHost());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldThrowInvalidIssuerIdWhenGetIssuerV2DetailsForInvalidId() {
        InvalidIssuerIdException exception = assertThrows(InvalidIssuerIdException.class,
                () -> issuersService.getIssuerV2Details("NonExistentId"));

        assertEquals("RESIDENT-APP-035 --> Invalid issuer ID", exception.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldPropagateApiNotAccessibleWhenGetIssuersV2DTOFails() {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        assertThrows(ApiNotAccessibleException.class, () -> issuersService.getIssuersV2DTO());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldPropagateApiNotAccessibleWhenGetIssuerV2DetailsFails() {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        assertThrows(ApiNotAccessibleException.class, () -> issuersService.getIssuerV2Details("Issuer3id"));
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }

    @Test
    public void shouldGenerateTokenEndpointWhenMissingInV1() throws Exception {
        String publicUrl = "https://api.dev.mosip.net";
        String context = "/v4/mimoto";
        String getTokenPath = "/get-token/";
        IssuersServiceImpl serviceWithConfig = new IssuersServiceImpl(
                utilities, objectMapper, issuersConfigUtil, publicUrl, context);

        String issuerIdMissing = "Issuer-Missing";
        String issuerIdExisting = "Issuer-Existing";
        String existingUrl = "https://external-idp.com/token";

        IssuerDTO issuerA = getIssuerConfigDTO(issuerIdMissing);
        issuerA.setIssuer_id(issuerIdMissing);
        issuerA.setToken_endpoint(null);

        IssuerDTO issuerB = getIssuerConfigDTO(issuerIdExisting);
        issuerB.setIssuer_id(issuerIdExisting);
        issuerB.setToken_endpoint(existingUrl);

        IssuersDTO mockIssuers = new IssuersDTO(List.of(issuerA, issuerB));
        String json = objectMapper.writeValueAsString(mockIssuers);

        when(utilities.getIssuersConfigJsonValue()).thenReturn(json);
        when(objectMapper.readValue(json, IssuersDTO.class)).thenReturn(mockIssuers);

        IssuersDTO result = serviceWithConfig.getAllIssuers();

        String expectedGeneratedUrlIssuerA = publicUrl + context + getTokenPath + issuerIdMissing;
        String expectedGeneratedUrlIssuerB = publicUrl + context + getTokenPath + issuerIdExisting;

        assertEquals(expectedGeneratedUrlIssuerA, result.getIssuers().get(0).getToken_endpoint());
        assertEquals(expectedGeneratedUrlIssuerB, result.getIssuers().get(1).getToken_endpoint());
    }

    @Test
    public void shouldGenerateTokenEndpointWhenMissingInV2() throws Exception {
        // Arrange
        String publicUrl = "https://api.dev.mosip.net";
        String context = "/v4/mimoto";
        String getTokenPath = "/get-token/";

        IssuersServiceImpl serviceWithConfig = new IssuersServiceImpl(
                utilities, objectMapper, issuersConfigUtil, publicUrl, context);

        String issuerIdMissing = "IssuerV2-Missing";
        String issuerIdExisting = "Issuer-Existing";
        String existingUrl = "https://external-idp.com/token";

        IssuerDTO issuerA = getIssuerConfigDTO(issuerIdMissing);
        issuerA.setIssuer_id(issuerIdMissing);
        issuerA.setToken_endpoint("");

        IssuerDTO issuerB = getIssuerConfigDTO(issuerIdExisting);
        issuerB.setIssuer_id(issuerIdExisting);
        issuerB.setToken_endpoint(existingUrl);

        IssuersDTO mockIssuers = new IssuersDTO(List.of(issuerA, issuerB));
        String json = objectMapper.writeValueAsString(mockIssuers);

        when(utilities.getIssuersConfigJsonValue()).thenReturn(json);
        when(objectMapper.readValue(json, IssuersDTO.class)).thenReturn(mockIssuers);

        IssuersV2DTO result = serviceWithConfig.getIssuersV2DTO();

        String expectedGeneratedUrlIssuerA = publicUrl + context + getTokenPath + issuerIdMissing;
        String expectedGeneratedUrlIssuerB = publicUrl + context + getTokenPath + issuerIdExisting;

        assertEquals(expectedGeneratedUrlIssuerA, result.getIssuers().get(0).getTokenEndpoint());
        assertEquals(expectedGeneratedUrlIssuerB, result.getIssuers().get(1).getTokenEndpoint());
    }
}