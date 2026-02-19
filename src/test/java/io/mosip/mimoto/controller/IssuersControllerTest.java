package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.Utilities;
import org.hamcrest.Matchers;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.List;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = IssuersController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class IssuersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IssuersServiceImpl issuersService;

    @MockBean
    private Utilities utilities;

    @MockBean
    ObjectMapper objectMapper;

    @Test
    public void getIssuersTest() throws Exception {
        IssuersDTO issuers = new IssuersDTO();
        issuers.setIssuers((List.of(getIssuerDTO("Issuer2"), getIssuerDTO("Issuer4"))));
        Mockito.when(issuersService.getIssuers())
                .thenReturn(issuers)
                .thenThrow(new ApiNotAccessibleException());

        IssuersDTO filteredIssuers = new IssuersDTO();
        filteredIssuers.setIssuers(issuers.getIssuers().stream().filter(issuer -> issuer.getDisplay().stream()
                        .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains("Issuer1".toLowerCase())))
                .collect(Collectors.toList()));

        Mockito.when(issuersService.getIssuers())
                .thenReturn(filteredIssuers)
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("issuer_id"),
                                Matchers.hasKey("credential_issuer"),
                                Matchers.hasKey("display"),
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey("wellknown_endpoint"),
                                Matchers.hasKey("proxy_token_endpoint"),
                                Matchers.hasKey("token_endpoint"),
                                Matchers.hasKey("credential_issuer_host"),
                                Matchers.hasKey("authorization_audience"),
                                Matchers.not(Matchers.hasKey("redirect_url")),
                                Matchers.not(Matchers.hasKey("authorization_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_audience")),
                                Matchers.not(Matchers.hasKey("additional_headers")),
                                Matchers.not(Matchers.hasKey("scopes_supported"))
                        )
                )));


        mockMvc.perform(get("/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }


    @Test
    public void getIssuerDetailsTestForValidIssuerId() throws Exception {
        Mockito.when(issuersService.getIssuerDetails("id1"))
                .thenReturn(getIssuerDTO("Issuer1"))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());

        mockMvc.perform(get("/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerDetailsTestForInvalidIssuerId() throws Exception {
        Mockito.when(issuersService.getIssuerDetails("invalidId")).thenThrow(InvalidIssuerIdException.class);

        mockMvc.perform(get("/issuers/invalidId").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerWellknownTest() throws Exception {
        String issuerId = "issuer1";
        String expectedCredentialIssuerWellknownResponse = getExpectedWellKnownJson();
        CredentialIssuerConfiguration expectedCredentialIssuerConfiguration = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(expectedCredentialIssuerConfiguration);

        String actualResponse = mockMvc.perform(get("/issuers/" + issuerId + "/well-known-proxy").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JSONAssert.assertEquals(new JSONObject(expectedCredentialIssuerWellknownResponse), new JSONObject(actualResponse), JSONCompareMode.LENIENT);
    }

    @Test
    public void getIssuerWellknownWhenServiceThrowsReturnsNotFound() throws Exception {
        String issuerId = "issuer1";
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenThrow(new RuntimeException("well-known unreachable"));

        mockMvc.perform(get("/issuers/" + issuerId + "/well-known-proxy").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound())
                .andExpect(result -> assertTrue(
                        result.getResponse().getContentAsString() == null || result.getResponse().getContentAsString().isEmpty()));
    }

    @Test
    public void getIssuerConfigurationTest() throws Exception {
        String issuerId = "id1";

        //get the IssuerConfig from the json file expectedIssuerConfig and wrap it inside response to test the response of configuration endpoint response wrapper
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode originalJson = objectMapper.readTree(new ClassPathResource("responses/expectedIssuerConfig.json").getInputStream());
        ObjectNode wrappedJson = objectMapper.createObjectNode();
        wrappedJson.set("response", originalJson);
        String expectedJsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(wrappedJson);
        if (expectedJsonString.startsWith("\uFEFF")) {
            expectedJsonString = expectedJsonString.substring(1);
        }
        String finalExpectedJsonString = expectedJsonString;
        CredentialIssuerConfiguration expectedCredentialIssuerConfiguration = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(expectedCredentialIssuerConfiguration);

        mockMvc.perform(get("/issuers/" + issuerId + "/configuration")
                        .accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    String actualResponse = result.getResponse().getContentAsString().trim();
                    JSONAssert.assertEquals(finalExpectedJsonString, actualResponse, JSONCompareMode.LENIENT);
                });
    }

    @Test
    public void shouldReturnExceptionInResponseOnGetIssuerConfigIfAnyExceptionOccurredWhenFetchingIssuerWellknown() throws Exception {
        String issuerId = "id1";
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/issuers/" + issuerId + "/configuration")
                        .accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }
}