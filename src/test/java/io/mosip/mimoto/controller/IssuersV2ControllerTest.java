package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.Utilities;
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

import java.io.IOException;
import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.getIssuerConfigDTO;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringRunner.class)
@SpringBootTest(classes = IssuersV2Controller.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class IssuersV2ControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IssuersServiceImpl issuersService;

    @MockBean
    private Utilities utilities;

    @Test
    public void getAllIssuers_WhenNoSearch_ReturnsOkAndIssuersList() throws Exception {
        IssuersDTO issuersDTO = new IssuersDTO();
        issuersDTO.setIssuers(List.of(getIssuerConfigDTO("IssuerA"), getIssuerConfigDTO("IssuerB")));
        Mockito.when(issuersService.getIssuers(null)).thenReturn(issuersDTO);

        mockMvc.perform(get("/v2/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.hasSize(2)))
                .andExpect(jsonPath("$.response.issuers[0].issuer_id", Matchers.anyOf(Matchers.is("IssuerAid"), Matchers.is("IssuerBid"))))
                .andExpect(jsonPath("$.response.issuers[*]", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("issuer_id"),
                                Matchers.hasKey("protocol"),
                                Matchers.hasKey("display"),
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey("token_endpoint"),
                                Matchers.hasKey("credential_issuer_host")
                        ))));
    }

    @Test
    public void getAllIssuers_WhenSearchProvided_ReturnsFilteredIssuers() throws Exception {
        IssuersDTO filtered = new IssuersDTO();
        filtered.setIssuers(List.of(getIssuerConfigDTO("IssuerX")));
        Mockito.when(issuersService.getIssuers("IssuerX")).thenReturn(filtered);

        mockMvc.perform(get("/v2/issuers").param("search", "IssuerX").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.hasSize(1)))
                .andExpect(jsonPath("$.response.issuers[0].issuer_id", Matchers.is("IssuerXid")));
    }

    @Test
    public void getAllIssuers_WhenServiceThrowsApiNotAccessible_ReturnsBadRequestWithError() throws Exception {
        Mockito.when(issuersService.getIssuers(null))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/v2/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getAllIssuers_WhenServiceThrowsIOException_ReturnsBadRequestWithError() throws Exception {
        Mockito.when(issuersService.getIssuers(null))
                .thenThrow(new IOException("config read failed"));

        mockMvc.perform(get("/v2/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())));
    }

    @Test
    public void getIssuerById_WhenIdValid_ReturnsOkAndIssuer() throws Exception {
        IssuerDTO issuer = getIssuerConfigDTO("MyIssuer");
        Mockito.when(issuersService.getIssuerDetails("MyIssuerid")).thenReturn(issuer);

        mockMvc.perform(get("/v2/issuers/MyIssuerid").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuer_id", Matchers.is("MyIssuerid")))
                .andExpect(jsonPath("$.response.protocol", Matchers.is("OpenId4VCI")))
                .andExpect(jsonPath("$.response.credential_issuer_host", Matchers.is("https://issuer.env.net")));
    }

    @Test
    public void getIssuerById_WhenIdInvalid_ReturnsNotFoundWithError() throws Exception {
        Mockito.when(issuersService.getIssuerDetails("NonExistent"))
                .thenThrow(new InvalidIssuerIdException());

        mockMvc.perform(get("/v2/issuers/NonExistent").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerById_WhenServiceThrowsApiNotAccessible_ReturnsBadRequestWithError() throws Exception {
        Mockito.when(issuersService.getIssuerDetails("id1"))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/v2/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())));
    }

    @Test
    public void getAllIssuers_WhenServiceThrowsGenericException_ReturnsBadRequestWithHandledError() throws Exception {
        String message = "Unexpected failure";
        Mockito.when(issuersService.getIssuers(null)).thenThrow(new RuntimeException(message));

        mockMvc.perform(get("/v2/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(message)));
    }

    @Test
    public void getIssuerById_WhenServiceThrowsGenericException_ReturnsBadRequestWithHandledError() throws Exception {
        String message = "Internal error";
        Mockito.when(issuersService.getIssuerDetails("id1")).thenThrow(new IllegalStateException(message));

        mockMvc.perform(get("/v2/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(message)));
    }
}
