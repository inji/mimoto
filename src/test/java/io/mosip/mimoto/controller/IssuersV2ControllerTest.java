package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.IssuerV2DTO;
import io.mosip.mimoto.dto.IssuersV2DTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.IssuersService;
import org.hamcrest.Matchers;
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
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.IOException;
import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.getIssuerResponseDTO;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = IssuersV2Controller.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class IssuersV2ControllerTest {

    private static final String LIST_PATH = "/v2/issuers";
    private static final String ISSUER_PATH = "/v2/issuers/{issuer-id}";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IssuersService issuersService;

    @Before
    public void setUp() {
        Mockito.reset(issuersService);
    }

    private ResultActions performGetList() throws Exception {
        return mockMvc.perform(get(LIST_PATH).accept(MediaType.APPLICATION_JSON_VALUE));
    }

    private ResultActions performGetIssuer(String issuerId) throws Exception {
        return mockMvc.perform(get(ISSUER_PATH, issuerId).accept(MediaType.APPLICATION_JSON_VALUE));
    }


    @Test
    public void getAllIssuersSuccessReturnsOkWithIssuersV2DTO() throws Exception {
        List<IssuerV2DTO> issuerList = List.of(getIssuerResponseDTO("IssuerA"), getIssuerResponseDTO("IssuerB"));
        Mockito.when(issuersService.getIssuersV2DTO()).thenReturn(new IssuersV2DTO(issuerList));

        performGetList()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.hasSize(2)))
                .andExpect(jsonPath("$.response.issuers[*].issuer_id", Matchers.everyItem(Matchers.anyOf(Matchers.is("IssuerAid"), Matchers.is("IssuerBid")))))
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
    public void getAllIssuersApiNotAccessibleExceptionReturnsBadRequestWithApiNotAccessibleError() throws Exception {
        Mockito.when(issuersService.getIssuersV2DTO()).thenThrow(new ApiNotAccessibleException());

        performGetList()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getAllIssuersIOExceptionReturnsBadRequestWithApiNotAccessibleError() throws Exception {
        Mockito.when(issuersService.getIssuersV2DTO()).thenThrow(new IOException("config read failed"));

        performGetList()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getAllIssuersGenericExceptionReturnsBadRequestWithHandledError() throws Exception {
        String message = "Unexpected failure";
        Mockito.when(issuersService.getIssuersV2DTO()).thenThrow(new RuntimeException(message));

        performGetList()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(message)));
    }


    @Test
    public void getIssuerByIdValidIdReturnsOkWithIssuerV2DTO() throws Exception {
        IssuerV2DTO issuer = getIssuerResponseDTO("MyIssuer");
        Mockito.when(issuersService.getIssuerV2Details("MyIssuerid")).thenReturn(issuer);

        performGetIssuer("MyIssuerid")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuer_id", Matchers.is("MyIssuerid")))
                .andExpect(jsonPath("$.response.protocol", Matchers.is("OpenId4VCI")))
                .andExpect(jsonPath("$.response.credential_issuer_host", Matchers.is("https://issuer.env.net")));
    }

    @Test
    public void getIssuerByIdInvalidIssuerIdExceptionReturnsNotFoundWithInvalidIssuerError() throws Exception {
        Mockito.when(issuersService.getIssuerV2Details("NonExistent")).thenThrow(new InvalidIssuerIdException());

        performGetIssuer("NonExistent")
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerByIdApiNotAccessibleExceptionReturnsBadRequestWithApiNotAccessibleError() throws Exception {
        Mockito.when(issuersService.getIssuerV2Details("id1")).thenThrow(new ApiNotAccessibleException());

        performGetIssuer("id1")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerByIdIOExceptionReturnsBadRequestWithApiNotAccessibleError() throws Exception {
        Mockito.when(issuersService.getIssuerV2Details("id1")).thenThrow(new IOException("io error"));

        performGetIssuer("id1")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerByIdGenericExceptionReturnsBadRequestWithHandledError() throws Exception {
        String message = "Internal error";
        Mockito.when(issuersService.getIssuerV2Details("id1")).thenThrow(new IllegalStateException(message));

        performGetIssuer("id1")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(message)));
    }
}
