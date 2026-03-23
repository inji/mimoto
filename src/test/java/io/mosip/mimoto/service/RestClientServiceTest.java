package io.mosip.mimoto.service;

import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.Lists;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.dto.AuditRequestDto;
import io.mosip.mimoto.dto.AuditResponseDto;
import io.mosip.mimoto.exception.ApisResourceAccessException;
import io.mosip.mimoto.service.impl.RestClientServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.web.client.ResourceAccessException;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class RestClientServiceTest {

    private static final String API_NAME = "AUDIT";

    @InjectMocks
    private RestClientServiceImpl registrationProcessorRestClientService;
    /** The rest api client. */
    @Mock
    private RestApiClient restApiClient;

    /** The env. */
    @Mock
    private Environment env;
    private AuditResponseDto auditResponseDto;

    @Before
    public void setUp() {
        auditResponseDto = new AuditResponseDto();
        auditResponseDto.setStatus(true);

    }

    @Test
    public void getObjectSuccessTest() throws Exception {

        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenReturn(auditResponseDto);
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.getApi(ApiName.AUDIT,
                null, "query1", "12345", AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test
    public void getSuccessTest() throws Exception {

        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenReturn(auditResponseDto);
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.getApi(ApiName.AUDIT,
                Lists.newArrayList("pathsegnemts"), Lists.newArrayList("query1"), Lists.newArrayList("12345"), AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test
    public void postObjecSuccessTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(auditResponseDto);
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.postApi(ApiName.AUDIT,
                "query1", "12345", auditRequestDto, AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test(expected = ApisResourceAccessException.class)
    public void getObjecTestFailureTest() throws Exception {
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        ResourceAccessException exp = new ResourceAccessException("errorMessage");
        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenThrow(exp);

        registrationProcessorRestClientService.getApi(ApiName.AUDIT, Arrays.asList("abc", "def"), "query1", "12345",
                AuditResponseDto.class);
    }

    @Test(expected = ApisResourceAccessException.class)
    public void getFailureTest() throws Exception {
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        ResourceAccessException exp = new ResourceAccessException("errorMessage");
        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenThrow(exp);

        registrationProcessorRestClientService.getApi(ApiName.AUDIT, Arrays.asList("abc", "def"),
                Lists.newArrayList("query1"), Lists.newArrayList("12345"),
                AuditResponseDto.class);
    }

    @Test(expected = ApisResourceAccessException.class)
    public void postObjecTestFailureTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        ResourceAccessException exp = new ResourceAccessException("errorMessage");
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(exp);
        registrationProcessorRestClientService.postApi(ApiName.AUDIT, "query1", "12345", auditRequestDto,
                AuditResponseDto.class);
    }

    @Test
    public void getObjectForArgListSuccessTest() throws Exception {

        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenReturn(auditResponseDto);
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.getApi(ApiName.AUDIT,
                null, Arrays.asList("query1"), Arrays.asList("12345"), AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test
    public void postObjectSuccessTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(auditResponseDto);
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.postApi(ApiName.AUDIT,
                pathSegments, "query1", "12345", auditRequestDto, AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test
    public void postSuccessTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.anyBoolean()))
                .thenReturn(auditResponseDto);
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.postApi(ApiName.AUDIT,
                auditRequestDto, AuditResponseDto.class, true);
        assertEquals(true, resultDto.isStatus());
    }

    @Test(expected = ApisResourceAccessException.class)
    public void postFailedTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.anyBoolean()))
                .thenThrow(new ApisResourceAccessException("Exception"));
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.postApi(ApiName.AUDIT,
                auditRequestDto, AuditResponseDto.class, true);
    }

    @Test(expected = ApisResourceAccessException.class)
    public void postObjectTestFailureTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        ResourceAccessException exp = new ResourceAccessException("errorMessage");
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(exp);
        registrationProcessorRestClientService.postApi(ApiName.AUDIT, pathSegments, "query1", "12345", auditRequestDto,
                AuditResponseDto.class);
    }

    @Test
    public void postObjectForArgListSuccessTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(auditResponseDto);
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        AuditResponseDto resultDto = (AuditResponseDto) registrationProcessorRestClientService.postApi(ApiName.AUDIT,
                null, pathSegments, Arrays.asList("query1"), Arrays.asList("12345"), auditRequestDto,
                AuditResponseDto.class);
        assertEquals(true, resultDto.isStatus());
    }

    @Test(expected = ApisResourceAccessException.class)
    public void postObjectForArgListTestFailureTest() throws Exception {
        AuditRequestDto auditRequestDto = new AuditRequestDto();
        Mockito.when(env.getProperty(ArgumentMatchers.any())).thenReturn(API_NAME);
        ResourceAccessException exp = new ResourceAccessException("errorMessage");
        List<String> pathSegments = new ArrayList<>();
        pathSegments.add("test");
        Mockito.when(restApiClient.postApi(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(exp);
        registrationProcessorRestClientService.postApi(ApiName.AUDIT, null, pathSegments, Arrays.asList("query1"),
                Arrays.asList("12345"), auditRequestDto, AuditResponseDto.class);
    }

}
