package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.mimoto.AttestationStatement;
import io.mosip.mimoto.util.AttestationOfflineVerify;
import io.mosip.mimoto.util.AttestationOnlineVerify;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringRunner.class)
@SpringBootTest(classes = AttestationServiceController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class AttestationServiceControllerTest {


    @MockBean
    private AttestationOfflineVerify attestationOfflineVerify;

    @MockBean
    private AttestationOnlineVerify attestationOnlineVerify;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void processOfflineTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOfflineVerify.parseAndVerify(Mockito.anyString())).thenReturn(attestationStatement);
        this.mockMvc.perform(post("/safetynet/offline/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOfflineFailureTest() throws Exception {
        Mockito.when(attestationOfflineVerify.parseAndVerify(Mockito.anyString())).thenThrow(new Exception("Exception"));
        this.mockMvc.perform(post("/safetynet/offline/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOnlineTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOnlineVerify.parseAndVerify(Mockito.anyString())).thenReturn(attestationStatement);
        this.mockMvc.perform(post("/safetynet/online/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOnlineFailureTest() throws Exception {
        Mockito.when(attestationOnlineVerify.parseAndVerify(Mockito.anyString())).thenThrow(new Exception("Exception"));
        this.mockMvc.perform(post("/safetynet/online/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

}