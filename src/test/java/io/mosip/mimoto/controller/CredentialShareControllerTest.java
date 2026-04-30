package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.AppCredentialRequestDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadRequestDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestResponseInnerResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestStatusResponseDTO;
import io.mosip.mimoto.model.Event;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import io.mosip.mimoto.util.RequestValidator;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.junit.Before;
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

import java.io.IOException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialShareController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class CredentialShareControllerTest {


    @Autowired
    private MockMvc mockMvc;

    @MockBean
    public RestApiClient restApiClient;


    @MockBean
    public RestClientService<Object> restClientService;

    @MockBean
    private CredentialShareServiceImpl credentialShareService;

    @MockBean
    Utilities utilities;

    @MockBean
    RequestValidator requestValidator;

    @Before
    public void setup() {
        Mockito.when(utilities.getDataPath()).thenReturn("target");
    }

    @Test
    public void handleSubscribeEventTest() throws Exception {
        Event event = new Event();
        event.setId("id");
        event.setTransactionId("transId");
        EventModel eventModel = new EventModel();
        eventModel.setEvent(event);

        Mockito.when(credentialShareService.generateDocuments(Mockito.any())).thenReturn(true);

        this.mockMvc.perform(post("/credentialshare/callback/notify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(eventModel)))
                .andExpect(status().isOk());
    }

    @Test
    public void requestTest() throws Exception {
        AppCredentialRequestDTO requestDTO = new AppCredentialRequestDTO();
        requestDTO.setUser("mono");
        requestDTO.setTransactionID("transactionId");
        requestDTO.setOtp("123456");
        requestDTO.setIndividualId("123456");
        requestDTO.setCredentialType("VERCRED");

        CredentialRequestResponseInnerResponseDTO dto = new CredentialRequestResponseInnerResponseDTO();
        dto.setRequestId("requestId");
        CredentialRequestResponseDTO response = new CredentialRequestResponseDTO();
        response.setResponse(dto);

        Mockito.when(restClientService.postApi(Mockito.any(), Mockito.anyString(), Mockito.anyString(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        Mockito.when(credentialShareService.generateDocuments(Mockito.any())).thenReturn(true);

        this.mockMvc.perform(post("/credentialshare/request").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void requestStatusTest() throws Exception {

        ResponseWrapper<CredentialRequestStatusResponseDTO> responseWrapper = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(), Mockito.anyString(), Mockito.anyString(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseWrapper);

        this.mockMvc.perform(get("/credentialshare/request/status/1234567890").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());
    }

    @Test
    public void downloadTest() throws Exception {

        CredentialDownloadRequestDTO requestDTO = new CredentialDownloadRequestDTO();
        requestDTO.setRequestId("requestId");
        requestDTO.setIndividualId("individualId");

        JsonNode credentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getVC(Mockito.anyString())).thenReturn(credentialJSON);

        JsonNode decryptedCredentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenReturn(decryptedCredentialJSON);

        JsonNode requestCredentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getRequestVC(Mockito.anyString())).thenReturn(requestCredentialJSON);

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());

        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenReturn(null);

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isNotFound());

        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenThrow(new IOException("Exception"));

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isNotFound());
    }
}