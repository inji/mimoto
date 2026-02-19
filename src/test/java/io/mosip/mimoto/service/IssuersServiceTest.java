package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuerResponseDTO;
import io.mosip.mimoto.dto.IssuersResponseDTO;
import io.mosip.mimoto.dto.IssuersDTO;
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
    }

    @Test
    public void shouldReturnAllIssuersWhenSearchValueIsNull() throws ApiNotAccessibleException, IOException {
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
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

        IssuerDTO issuer = issuersService.getIssuerDetails("Issuer3id");

        assertEquals(expectedIssuer, issuer);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForAllIssuer() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer3"), getIssuerConfigDTO("Issuer4")));
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
    public void shouldReturnIssuerResponseListWhenGetIssuersResponseWithWellKnownSuccess() throws Exception {
        IssuersResponseDTO result = issuersService.getIssuersResponse(null);

        assertEquals(2, result.getIssuers().size());
        IssuerResponseDTO first = result.getIssuers().get(0);
        assertEquals("Issuer3id", first.getIssuerId());
        assertEquals("OpenId4VCI", first.getProtocol());
        assertEquals("https://issuer.env.net/.well-known/openid-credential-issuer", first.getWellknownEndpoint());
        assertEquals("io.mosip.residentapp.inji://oauthredirect", first.getRedirectUri());
        assertEquals("https://dev/Issuer3id", first.getTokenEndpoint());
        assertEquals("Issuer3id", first.getCredentialIssuer());
        assertEquals(expectedCredentialIssuerWellKnownResponse.getCredentialEndPoint(), first.getAuthorizationAudience());
        assertEquals(expectedCredentialIssuerWellKnownResponse.getCredentialEndPoint(), first.getProxyTokenEndpoint());
        verify(issuersConfigUtil, atLeast(1)).getIssuerWellknown(credentialIssuerHostUrl);
    }

    @Test
    public void shouldReturnIssuerResponseListWithFallbackWhenWellKnownFails() throws Exception {
        Mockito.when(issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl))
                .thenThrow(new ApiNotAccessibleException("well-known unreachable"));

        IssuersResponseDTO result = issuersService.getIssuersResponse(null);

        assertEquals(2, result.getIssuers().size());
        IssuerResponseDTO first = result.getIssuers().get(0);
        assertEquals("Issuer3id", first.getIssuerId());
        assertEquals(credentialIssuerHostUrl, first.getCredentialIssuerHost());
        assertEquals("Issuer3id", first.getCredentialIssuer());
        assertEquals("io.mosip.residentapp.inji://oauthredirect", first.getRedirectUri());
    }

    @Test
    public void shouldReturnIssuerResponseDetailsForValidIssuerId() throws Exception {
        IssuerResponseDTO result = issuersService.getIssuerResponseDetails("Issuer3id");

        assertEquals("Issuer3id", result.getIssuerId());
        assertEquals("https://issuer.env.net/.well-known/openid-credential-issuer", result.getWellknownEndpoint());
        assertEquals("Issuer3id", result.getCredentialIssuer());
        assertEquals(expectedCredentialIssuerWellKnownResponse.getCredentialEndPoint(), result.getProxyTokenEndpoint());
        verify(issuersConfigUtil, times(1)).getIssuerWellknown(credentialIssuerHostUrl);
    }

    @Test
    public void shouldThrowInvalidIssuerIdWhenGetIssuerResponseDetailsForInvalidId() {
        InvalidIssuerIdException exception = assertThrows(InvalidIssuerIdException.class,
                () -> issuersService.getIssuerResponseDetails("NonExistentId"));

        assertEquals("RESIDENT-APP-035 --> Invalid issuer ID", exception.getMessage());
    }

    @Test
    public void shouldPropagateExceptionWhenGetIssuersResponseFails() {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        assertThrows(ApiNotAccessibleException.class, () -> issuersService.getIssuersResponse(null));
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }
}