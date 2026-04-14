package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.util.parser.WellknownParserFactory;
import io.mosip.mimoto.util.parser.WellknownResponseParser;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class IssuerConfigUtilTest {

    @InjectMocks
    IssuerConfigUtil issuersConfigUtil;

    @Mock
    RestApiClient restApiClient;

    @Mock
    ObjectMapper objectMapper;

    @Mock
    Validator validator;

    @Mock
    CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator;

    @Mock
    VCSpecVersionDetector versionDetector;

    @Mock
    WellknownParserFactory parserFactory;

    @Mock
    WellknownResponseParser wellknownResponseParser;

    String authorizationServerWellknownUrl, authorizationServerHostUrl, issuerWellKnownUrl,exceptionMsgPrefix, issuerId, credentialIssuerHostUrl, authServerWellknownUrl;

    CredentialIssuerWellKnownResponse expectedCredentialIssuerWellKnownResponse;


    @Before
    public void setUp() throws Exception {
        authorizationServerWellknownUrl = "https://dev/authorize/.well-known/oauth-authorization-server";
        authorizationServerHostUrl = "https://dev/authorize";
        exceptionMsgPrefix = "RESIDENT-APP-042 --> Invalid Authorization Server well-known from server:\n";

        credentialIssuerHostUrl = "https://issuer.env.net";
        issuerWellKnownUrl = "https://issuer.env.net/.well-known/openid-credential-issuer";
        expectedCredentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        String expectedWellknownJson = getExpectedWellKnownJson();
        Mockito.when(restApiClient.getApi(issuerWellKnownUrl, String.class))
                .thenReturn(expectedWellknownJson);
        Mockito.when(objectMapper.readTree(expectedWellknownJson))
                .thenReturn(Mockito.mock(JsonNode.class));
        Mockito.when(versionDetector.detectVersion(any(JsonNode.class)))
                .thenReturn(VCSpecificationVersion.DRAFT_13);
        Mockito.when(parserFactory.getParser(eq(VCSpecificationVersion.DRAFT_13)))
                .thenReturn(wellknownResponseParser);
        Mockito.when(wellknownResponseParser.parse(expectedWellknownJson))
                .thenReturn(expectedCredentialIssuerWellKnownResponse);
    }

    @Test
    public void shouldThrowExceptionIfResponseIsNullWhenGettingAuthServerWellknownConfig() {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: well-known api is not accessible";
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(null);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }

    @Test
    public void shouldThrowExceptionIfAuthorizationEndpointIsMissingInAuthServerWellknownResponse() throws Exception {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: Validation failed:\n" + "authorizationEndpoint: must not be blank";
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of("authorization_endpoint"));
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }

    @Test
    public void shouldReturnResponseIfTheAuthServerHostUrlAndWellknownResponseAreValid() throws Exception {
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of());
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellKnownResponse actualAuthorizationServerWellKnownResponse = issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);

        assertEquals(expectedAuthorizationServerWellKnownResponse, actualAuthorizationServerWellKnownResponse);
    }

    @Test
    public void shouldReturnIssuerWellknownForTheRequestedIssuerId() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse actualCredentialIssuerWellKnownResponse = issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl);

        assertEquals(expectedCredentialIssuerWellKnownResponse, actualCredentialIssuerWellKnownResponse);
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
        verify(parserFactory, times(1)).getParser(eq(VCSpecificationVersion.DRAFT_13));
        verify(wellknownResponseParser, times(1)).validate(eq(expectedCredentialIssuerWellKnownResponse), eq(validator));
    }

    @Test
    public void shouldThrowExceptionIfAnyIssuerOccurredWhileFetchingIssuerWellknown() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        Mockito.when(restApiClient.getApi(issuerWellKnownUrl, String.class))
                .thenReturn(null);

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> {
            issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl);
        });

        assertEquals("RESIDENT-APP-026 --> Api not accessible failure", actualException.getMessage());
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
    }

    @Test
    public void testCamelToTitleCaseNullInput() {
        String result = issuersConfigUtil.camelToTitleCase(null);
        assertNull(result);
    }

    @Test
    public void testCamelToTitleCaseEmptyInput() {
        String result = issuersConfigUtil.camelToTitleCase("");
        assertEquals("", result);
    }

    @Test
    public void testCamelToTitleCaseSingleWord() {
        String result = issuersConfigUtil.camelToTitleCase("name");
        assertEquals("Name", result);
    }

    @Test
    public void testCamelToTitleCaseCamelCase() {
        String result = issuersConfigUtil.camelToTitleCase("firstName");
        assertEquals("First Name", result);
    }

    @Test
    public void testCamelToTitleCaseMultipleCamelCase() {
        String result = issuersConfigUtil.camelToTitleCase("firstNameAndLastName");
        assertEquals("First Name And Last Name", result);
    }

    @Test
    public void testCamelToTitleCaseWithAcronym() {
        String result = issuersConfigUtil.camelToTitleCase("PRACondition");
        assertEquals("PRA Condition", result);
    }

    @Test
    public void testCamelToTitleCaseAcronymAtEnd() {
        String result = issuersConfigUtil.camelToTitleCase("conditionPRA");
        assertEquals("Condition PRA", result);
    }

    @Test
    public void testCamelToTitleCaseAllUppercase() {
        String result = issuersConfigUtil.camelToTitleCase("URL");
        assertEquals("URL", result);
    }

    @Test
    public void testCamelToTitleCaseMixedCase() {
        String result = issuersConfigUtil.camelToTitleCase("pinFor");
        assertEquals("Pin For", result);
    }

}

