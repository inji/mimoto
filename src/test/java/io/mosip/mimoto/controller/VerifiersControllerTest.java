package io.mosip.mimoto.controller;

import io.mosip.openID4VP.constants.SpecVersion;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.VerifierServiceImpl;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = VerifiersController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class VerifiersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VerifierServiceImpl verifierService;


    @Test
    public void getAllTrustedVerifiers() throws Exception {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri")).build();

        VerifiersDTO trustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        Mockito.when(verifierService.getTrustedVerifiers())
                .thenReturn(trustedVerifiers);


        mockMvc.perform(get("/verifiers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.verifiers", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey("redirect_uris"),
                                Matchers.hasKey("response_uris")
                        )
                )));
    }

    @Test
    public void shouldReturnEmptyResponseIfAnyErrorOccurredWhileFetchingVerifiersList() throws Exception {
        Mockito.when(verifierService.getTrustedVerifiers())
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/verifiers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.response.verifiers").isArray())
                .andExpect(jsonPath("$.response.verifiers").isEmpty());
    }

    @Test
    public void shouldIncludeAllProvidedPropertiesInTrustedVerifiers() throws Exception {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("client_name", "Test-Verifier");

        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri"))
                .jwksUri("https://test/.well-known/jwks.json")
                .allowUnsignedRequest(true)
                .specVersion(SpecVersion.DRAFT_23)
                .build();

        VerifiersDTO trustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        Mockito.when(verifierService.getTrustedVerifiers())
                .thenReturn(trustedVerifiers);

        mockMvc.perform(get("/verifiers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.verifiers[0].allow_unsigned_request").value(true))
                .andExpect(jsonPath("$.response.verifiers[0].client_id").value("test-clientId"))
                .andExpect(jsonPath("$.response.verifiers[0].spec_version").value("draft23"))
                .andExpect(jsonPath("$.response.verifiers[0].jwks_uri").value("https://test/.well-known/jwks.json"));
    }

    @Test
    public void shouldReturnDefaultValuesWhenOptionalFieldsAreNotProvided() throws Exception {
        // Not providing jwks_uri and allow_unsigned_request in VerifierDTO
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri"))
                .build();

        VerifiersDTO trustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        Mockito.when(verifierService.getTrustedVerifiers())
                .thenReturn(trustedVerifiers);

        mockMvc.perform(get("/verifiers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.verifiers[0].allow_unsigned_request").value(false)) // allow_unsigned_request is not passed means it should take default value false
                .andExpect(jsonPath("$.response.verifiers[0].spec_version").value("v1")) // spec version is not passed means it should take default value v1
                .andExpect(jsonPath("$.response.verifiers[0].jwks_uri").doesNotExist()); // jwks_uri is not passed means it should not be present in trusted verifiers
    }
}
