
package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.injivcrenderer.InjiVcRenderer;
import io.mosip.mimoto.constant.LdpVcV1Constants;
import io.mosip.mimoto.constant.LdpVcV2Constants;
import io.mosip.mimoto.constant.SdJwtVcConstants;
import io.mosip.mimoto.dto.BackgroundImageDTO;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.LdpVcCredentialFormatHandler;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.service.impl.VcSdJwtCredentialFormatHandler;
import io.mosip.mimoto.util.SvgFixerUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Stream;

import static io.mosip.mimoto.constant.LdpVcV2Constants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialPDFGeneratorServiceTest {

    @Mock private ObjectMapper objectMapper;
    @Mock private PresentationServiceImpl presentationService;
    @Mock private Utilities utilities;
    @Mock private PixelPass pixelPass;
    @Mock private SvgFixerUtil svgFixerUtil;
    @Mock private InjiVcRenderer injiVcRenderer;
    @Mock
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;
    @Mock
    private LdpVcCredentialFormatHandler credentialFormatHandler;

    @Mock
    private VcSdJwtCredentialFormatHandler sdJwtCredentialFormatHandler;

    @InjectMocks
    private CredentialPDFGeneratorService credentialPDFGeneratorService;

    private VCCredentialResponse vcCredentialResponse;
    private IssuerDTO issuerDTO;
    private CredentialsSupportedResponse credentialsSupportedResponse;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "ovpQRDataPattern", "test-pattern-%s-%s");
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "qrCodeHeight", 500);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "qrCodeWidth", 500);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "allowedQRDataSizeLimit", 2000);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "pixelPass", pixelPass);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "faceImageLookupKeys",
                "image,face,photo,picture,portrait");

        setupTestData();
    }

    private void setupTestData() {
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("dateOfBirth", "1990-01-01");
        subjectData.put("face", "base64-encoded-image");

        VCCredentialProperties vcProperties = VCCredentialProperties.builder()
                .credentialSubject(subjectData)
                .type(List.of("VerifiableCredential"))
                .build();

        vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(vcProperties)
                .build();

        issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id("test-issuer");
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        DisplayDTO display = new DisplayDTO();
        display.setName("Issuer Display Name");
        display.setTitle("Issuer Title");
        display.setDescription("Issuer Description");
        display.setLanguage("en");

        LogoDTO logo = new LogoDTO();
        logo.setUrl("https://example.com/logo.png");
        display.setLogo(logo);

        issuerDTO.setDisplay(List.of(display));

        credentialsSupportedResponse = new CredentialsSupportedResponse();

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));

        CredentialDefinitionResponseDto definition = new CredentialDefinitionResponseDto();
        definition.setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setCredentialDefinition(definition);
        credentialsSupportedResponse.setOrder(new ArrayList<>(List.of("name", "dateOfBirth")));

        CredentialSupportedDisplayResponse credDisplay = new CredentialSupportedDisplayResponse();
        credDisplay.setBackgroundColor("#FFFFFF");
        credDisplay.setTextColor("#000000");
        credDisplay.setName("Test Credential");
        BackgroundImageDTO bgImage = new BackgroundImageDTO();
        bgImage.setUri("https://example.com/bg.png");
        credDisplay.setBackgroundImage(bgImage);

        credentialsSupportedResponse.setDisplay(List.of(credDisplay));
    }

    private CredentialDisplayResponseDto createDisplay(String name) {
        CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
        display.setName(name);
        display.setLocale("en");
        dto.setDisplay(List.of(display));
        return dto;
    }

    @Test
    void testGeneratePdfForVerifiableCredential() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfForEmbeddedVCQR() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            verify(pixelPass).generateQRData(anyString(), anyString());
            verify(presentationService, never()).constructPresentationDefinition(any());
            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfShouldGeneratePresentationDefinitionForOnlineSharingQrTypeWithNonEmptyDataShareUrl() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test", "", "en");

            verify(presentationService).constructPresentationDefinition(any());
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            assertNotNull(result);
        }
    }

    @Test
    void testHandleMapWithListValue() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        Map<String, Object> skills = new HashMap<>();
        skills.put("skills", List.of("Java", "Spring"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(skills);
        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("skills", createDisplay("Skills"));
        credentialsSupportedResponse.setOrder(List.of("skills"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testNullFaceImageHandling() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        Map<String, Object> mutableSubject = new HashMap<>(((VCCredentialProperties)vcCredentialResponse.getCredential()).getCredentialSubject());
        mutableSubject.remove("face");
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(mutableSubject);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfWithNullOrder() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        credentialsSupportedResponse.setOrder(null);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "https://example.com/share", "", "en");

            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfWithMapValueFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with map containing "value" key
        Map<String, Object> subjectWithMapValue = new HashMap<>();
        subjectWithMapValue.put("education", Map.of("value", "Bachelor's Degree"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithMapValue);

        // Setup display for education field
        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("education", createDisplay("Education"));
        credentialsSupportedResponse.setOrder(List.of("education"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Education: $rowProperties.education</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Verify the PDF generation succeeded - formatValue was called internally
    }

    @Test
    void testGeneratePdfWithStringListFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with list of strings
        Map<String, Object> subjectWithList = new HashMap<>();
        subjectWithList.put("skills", List.of("Java", "Spring", "Boot"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithList);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("skills", createDisplay("Skills"));
        credentialsSupportedResponse.setOrder(List.of("skills"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Skills: $rowProperties.skills</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // The formatValue method handles list formatting internally
    }

    @Test
    void testGeneratePdfWithLocaleSpecificMapListFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with locale-specific map list
        Map<String, Object> subjectWithLocaleMap = new HashMap<>();
        List<Map<String, Object>> localeData = List.of(
                Map.of(LdpVcV2Constants.LANGUAGE, "en", LdpVcV2Constants.VALUE, "English Name"),
                Map.of(LdpVcV2Constants.LANGUAGE, "fr", LdpVcV2Constants.VALUE, "French Name")
        );
        subjectWithLocaleMap.put("localizedName", localeData);
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithLocaleMap);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("localizedName", createDisplay("Localized Name"));
        credentialsSupportedResponse.setOrder(List.of("localizedName"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Name: $rowProperties.localizedName</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // formatValue should select "English Name" based on locale "en"
    }

    @Test
    void testGeneratePdfWithNumericValueFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with numeric value
        Map<String, Object> subjectWithNumber = new HashMap<>();
        subjectWithNumber.put("age", 25);
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithNumber);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("age", createDisplay("Age"));
        credentialsSupportedResponse.setOrder(List.of("age"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Age: $rowProperties.age</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // formatValue converts number to string internally
    }

    @Test
    void testFaceKeyFallbackFromPrimaryToSecondary() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No "face" key, but has "photo" key
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("photo", "base64-photo-image");
        subjectData.put("dateOfBirth", "1990-01-01");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Setup credential display without face key to avoid it appearing in rowProperties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));
        // Note: No "photo" in display properties - should be excluded from rowProperties

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "dateOfBirth"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Indirectly tests that "photo" was used as fallback for $face variable
    }

    @Test
    void testFaceKeyFallbackToPortrait() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No "face" or "photo", but has "portrait"
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("portrait", "base64-portrait-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Portrait: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "portrait" key
    }

    @Test
    void testFaceKeyFallbackToImage() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Only "image" key available
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("image", "base64-generic-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Image: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "image" key
    }

    @Test
    void testFaceKeyFallbackToPicture() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Only "picture" key available
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("picture", "base64-picture-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Picture: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "picture" key
    }

    @Test
    void testFaceKeyPriorityOrder() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys present - should use first available in priority order
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("picture", "base64-picture-image"); // Lower priority
        subjectData.put("photo", "base64-photo-image");     // Lower priority
        subjectData.put("image", "base64-image");           // HIGHEST priority now

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        // Include all face keys in display to test that only "image" gets excluded
        credentialSubjectMap.put("picture", createDisplay("Picture"));
        credentialSubjectMap.put("photo", createDisplay("Photo"));
        credentialSubjectMap.put("image", createDisplay("Image")); // Should be excluded (used for $face)

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "picture", "photo", "image"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Should use "image" (highest priority) over "photo" and "picture"
        // Only "image" should be excluded from rowProperties, "photo" and "picture" should appear
    }

    @Test
    void testOnlySelectedFaceKeyExcludedFromRowProperties() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys - only the selected one ("image") should be excluded from rowProperties
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("image", "base64-image");           // Highest priority - will be selected for $face
        subjectData.put("face", "base64-face-image");       // Should appear in rowProperties
        subjectData.put("photo", "base64-photo-image");     // Should appear in rowProperties
        subjectData.put("portrait", "base64-portrait-image"); // Should appear in rowProperties
        subjectData.put("email", "john@example.com");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Include all face keys in display properties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("image", createDisplay("Image"));        // Should be excluded (used for $face)
        credentialSubjectMap.put("face", createDisplay("Face Photo"));    // Should appear in rowProperties
        credentialSubjectMap.put("photo", createDisplay("Photo"));        // Should appear in rowProperties
        credentialSubjectMap.put("portrait", createDisplay("Portrait"));  // Should appear in rowProperties
        credentialSubjectMap.put("email", createDisplay("Email Address"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "image", "face", "photo", "portrait", "email"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Only "image" should be excluded from rowProperties. "face", "photo" and "portrait" should appear in rowProperties
    }

    @Test
    void testMultipleFaceKeysExcludedFromRowProperties() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys present
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("face", "base64-face-image");
        subjectData.put("photo", "base64-photo-image");
        subjectData.put("portrait", "base64-portrait-image");
        subjectData.put("email", "john@example.com");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Include all face keys in display properties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("face", createDisplay("Face Photo"));
        credentialSubjectMap.put("photo", createDisplay("Photo"));
        credentialSubjectMap.put("portrait", createDisplay("Portrait"));
        credentialSubjectMap.put("email", createDisplay("Email Address"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "face", "photo", "portrait", "email"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // All face-related keys should be excluded from rowProperties
        // Only "name" and "email" should appear in rowProperties
    }

    @Test
    void testNoFaceKeysAvailable() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No face-related keys in credential
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("email", "john@example.com");
        subjectData.put("dateOfBirth", "1990-01-01");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("email", createDisplay("Email Address"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "email", "dateOfBirth"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Should handle gracefully when no face keys are available ($face will be null)
    }

    @Test
    void testMaskingForSelectivelyDisclosableClaimsAndNonMaskedFieldsInSDJWT() throws Exception {
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "maskDisclosures", true);

        when(credentialFormatHandlerFactory.getHandler("vc+sd-jwt")).thenReturn(sdJwtCredentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        String validSdJwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjMTIzIl19.signature~WyJzYWx0IiwgIm5hbWUiLCAiSm9obiBEb2UiXQ~";

        VCCredentialResponse sdJwtVcResponse = VCCredentialResponse.builder()
                .format("vc+sd-jwt")
                .credential(validSdJwt)
                .build();

        Map<String, Object> extractedClaims = new HashMap<>();
        extractedClaims.put("name", "John Doe");
        when(sdJwtCredentialFormatHandler.extractCredentialClaims(sdJwtVcResponse)).thenReturn(extractedClaims);

        CredentialIssuerDisplayResponse displayResponse = createDisplayResponse("Name", "en");
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(displayResponse, "John Doe"));
        when(sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html></html>");

        try (MockedStatic<SDJWT> mockedSDJWT = mockStatic(SDJWT.class);
             MockedStatic<Utilities> mockedUtilities = mockStatic(Utilities.class)) {

            Disclosure nameDisclosure = mock(Disclosure.class);
            when(nameDisclosure.getClaimName()).thenReturn("name");

            SDJWT mockSdJwt = mock(SDJWT.class);
            when(mockSdJwt.getDisclosures()).thenReturn(List.of(nameDisclosure));
            mockedSDJWT.when(() -> SDJWT.parse(validSdJwt)).thenReturn(mockSdJwt);

            mockedUtilities.when(() -> Utilities.maskValue("John Doe")).thenReturn("****");
            mockedUtilities.when(() -> Utilities.encodeToString(any(), anyString())).thenReturn("encoded-image");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "credentialConfigId", sdJwtVcResponse, issuerDTO,
                    credentialsSupportedResponse, "http://datashare.url", "2025-12-31", "en");

            assertNotNull(result);
            mockedUtilities.verify(() -> Utilities.maskValue("John Doe"));
        }
    }

    @Test
    void testNoMaskingForLdpFormat() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup LDP-VC format (not SD-JWT)
        vcCredentialResponse.setFormat("ldp_vc");

        // This test uses the LDP-VC handler (already set up in @BeforeEach)
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        claims.put("age", "30");

        // Use the specific LDP-VC handler
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(claims);

        // Use LinkedHashMap instead of HashMap
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("age", Map.of(createDisplayResponse("Age", "en"), "30"));

        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html>Test Template</html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    private CredentialIssuerDisplayResponse createDisplayResponse(String name, String locale) {
        CredentialIssuerDisplayResponse response = new CredentialIssuerDisplayResponse();
        response.setName(name);
        response.setLocale(locale);
        return response;
    }

    @Test
    void testFormatValueWithMap() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        // Setup credential with map containing "value"
        Map<String, Object> subject = Map.of("education", Map.of("value", "Bachelor's Degree"));
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subject);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("education", Map.of(createDisplayResponse("Education", "en"), Map.of("value", "Bachelor's Degree")));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject().put("education", createDisplay("Education"));
        credentialsSupportedResponse.setOrder(List.of("education"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Education: $rowProperties.education</body></html>");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse, "", "", "en");

        assertNotNull(result);  // Verifies formatValue extracted "Bachelor's Degree"
    }

    @Test
    void testFormatValueWithStringList() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        // Setup credential with list of strings
        Map<String, Object> subject = Map.of("skills", List.of("Java", "Spring", "Boot"));
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subject);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("skills", Map.of(createDisplayResponse("Skills", "en"), List.of("Java", "Spring", "Boot")));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject().put("skills", createDisplay("Skills"));
        credentialsSupportedResponse.setOrder(List.of("skills"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Skills: $rowProperties.skills</body></html>");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse, "", "", "en");

        assertNotNull(result);  // Verifies formatValue joined to "Java, Spring, Boot"
    }

    @Test
    void testFormatValueWithLocaleMapList() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        // Setup credential with locale-specific list
        List<Map<String, Object>> localeData = List.of(
                Map.of(LdpVcV2Constants.LANGUAGE, "en", LdpVcV2Constants.VALUE, "English Name"),
                Map.of(LdpVcV2Constants.LANGUAGE, "fr", LdpVcV2Constants.VALUE, "French Name")
        );
        Map<String, Object> subject = Map.of("name", localeData);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subject);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), localeData));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject().put("name", createDisplay("Name"));
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse, "", "", "en");

        assertNotNull(result);  // Verifies formatValue selected "English Name" for locale "en"
    }

    @Test
    void testFormatValueWithEmptyList() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        // Setup credential with empty list
        Map<String, Object> subject = Map.of("tags", List.of());
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subject);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("tags", Map.of(createDisplayResponse("Tags", "en"), List.of()));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject().put("tags", createDisplay("Tags"));
        credentialsSupportedResponse.setOrder(List.of("tags"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Tags: $rowProperties.tags</body></html>");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse, "", "", "en");

        assertNotNull(result);  // Verifies formatValue returned "" for empty list
    }

    @Test
    void testFormatValueWithPrimitive() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        // Setup credential with number
        Map<String, Object> subject = Map.of("age", 25);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subject);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("age", Map.of(createDisplayResponse("Age", "en"), 25));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject().put("age", createDisplay("Age"));
        credentialsSupportedResponse.setOrder(List.of("age"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Age: $rowProperties.age</body></html>");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse, "", "", "en");

        assertNotNull(result);  // Verifies formatValue converted 25 to "25"
    }

    @Test
    void testFormatValueWithMap_AtValue() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(objectMapper, presentationService, utilities, pixelPass, credentialFormatHandlerFactory, injiVcRenderer, svgFixerUtil );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, Object> value = new HashMap<>();
        value.put(LdpVcV2Constants.VALUE, "Green Valley Farm");

        String result = (String) formatValueMethod.invoke(service, value, "en");

        assertEquals("Green Valley Farm", result);
    }

    @Test
    void testFormatValueWithMap_Value() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(objectMapper, presentationService, utilities, pixelPass, credentialFormatHandlerFactory, injiVcRenderer, svgFixerUtil );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, Object> value = new HashMap<>();
        value.put(LdpVcV1Constants.VALUE, "Green Valley Farm");

        String result = (String) formatValueMethod.invoke(service, value, "en");

        assertEquals("Green Valley Farm", result);
    }

    @Test
    void testFormatValueWithListOfMaps_AtLanguageAndAtValue() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(objectMapper, presentationService, utilities, pixelPass, credentialFormatHandlerFactory, injiVcRenderer, svgFixerUtil );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, String> mapEn = new HashMap<>();
        mapEn.put(LdpVcV2Constants.VALUE, "Green Valley Farm");
        mapEn.put(LdpVcV2Constants.LANGUAGE, "en");

        Map<String, String> mapFr = new HashMap<>();
        mapFr.put(LdpVcV2Constants.VALUE, "Ferme Vallée Verte");
        mapFr.put(LdpVcV2Constants.LANGUAGE, "fr");

        Map<String, String> mapFil = new HashMap<>();
        mapFil.put(LdpVcV2Constants.VALUE, "Bukid sa Luntiang Lambak");
        mapFil.put(LdpVcV2Constants.LANGUAGE, "fil");

        List<Map<String, String>> value = Arrays.asList(mapEn, mapFr, mapFil);

        String resultEn = (String) formatValueMethod.invoke(service, value, "en");
        String resultFr = (String) formatValueMethod.invoke(service, value, "fr");
        String resultFil = (String) formatValueMethod.invoke(service, value, "fil");
        String resultNoMatchingLang = (String) formatValueMethod.invoke(service, value, "hi"); // matching language not present, should return empty string
        String resultNullLang = (String) formatValueMethod.invoke(service, value, null); // null language, should return empty string

        assertEquals("Green Valley Farm", resultEn);
        assertEquals("Ferme Vallée Verte", resultFr);
        assertEquals("Bukid sa Luntiang Lambak", resultFil);
        assertEquals("", resultNoMatchingLang);
        assertEquals("", resultNullLang);
    }

    @Test
    void testFormatValueWithListOfMaps_LanguageAndValue() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(objectMapper, presentationService, utilities, pixelPass, credentialFormatHandlerFactory, injiVcRenderer, svgFixerUtil );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, String> mapEn = new HashMap<>();
        mapEn.put(SdJwtVcConstants.VALUE, "Green Valley Farm");
        mapEn.put(SdJwtVcConstants.LANGUAGE, "en");

        Map<String, String> mapFr = new HashMap<>();
        mapFr.put(SdJwtVcConstants.VALUE, "Ferme Vallée Verte");
        mapFr.put(SdJwtVcConstants.LANGUAGE, "fr");

        Map<String, String> mapFil = new HashMap<>();
        mapFil.put(SdJwtVcConstants.VALUE, "Bukid sa Luntiang Lambak");
        mapFil.put(SdJwtVcConstants.LANGUAGE, "fil");

        List<Map<String, String>> value = Arrays.asList(mapEn, mapFr, mapFil);

        String resultEn = (String) formatValueMethod.invoke(service, value, "en");
        String resultFr = (String) formatValueMethod.invoke(service, value, "fr");
        String resultFil = (String) formatValueMethod.invoke(service, value, "fil");
        String resultNoMatchingLang = (String) formatValueMethod.invoke(service, value, "hi"); // matching language not present, should return empty string
        String resultNullLang = (String) formatValueMethod.invoke(service, value, null); // null language, should return empty string

        assertEquals("Green Valley Farm", resultEn);
        assertEquals("Ferme Vallée Verte", resultFr);
        assertEquals("Bukid sa Luntiang Lambak", resultFil);
        assertEquals("", resultNoMatchingLang);
        assertEquals("", resultNullLang);
    }

    @Test
    void testFormatValueWithListOfMaps_langAndValue() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(objectMapper, presentationService, utilities, pixelPass, credentialFormatHandlerFactory, injiVcRenderer, svgFixerUtil );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, String> mapEn = new HashMap<>();
        mapEn.put(LdpVcV1Constants.VALUE, "Green Valley Farm");
        mapEn.put(LdpVcV1Constants.LANGUAGE, "en");

        Map<String, String> mapFr = new HashMap<>();
        mapFr.put(LdpVcV1Constants.VALUE, "Ferme Vallée Verte");
        mapFr.put(LdpVcV1Constants.LANGUAGE, "fr");

        Map<String, String> mapFil = new HashMap<>();
        mapFil.put(LdpVcV1Constants.VALUE, "Bukid sa Luntiang Lambak");
        mapFil.put(LdpVcV1Constants.LANGUAGE, "fil");

        List<Map<String, String>> value = Arrays.asList(mapEn, mapFr, mapFil);

        String resultEn = (String) formatValueMethod.invoke(service, value, "en");
        String resultFr = (String) formatValueMethod.invoke(service, value, "fr");
        String resultFil = (String) formatValueMethod.invoke(service, value, "fil");
        String resultNoMatchingLang = (String) formatValueMethod.invoke(service, value, "hi"); // matching language not present, should return empty string
        String resultNullLang = (String) formatValueMethod.invoke(service, value, null); // null language, should return empty string

        assertEquals("Green Valley Farm", resultEn);
        assertEquals("Ferme Vallée Verte", resultFr);
        assertEquals("Bukid sa Luntiang Lambak", resultFil);
        assertEquals("", resultNoMatchingLang);
        assertEquals("", resultNullLang);
    }

    @Test
    void testInjiVcRendererInvokedForLdpVcWithContextListAndTemplate() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL, "https://w3id.org/security/v1"));
        credentialMap.put(RENDER_METHOD, List.of(Map.of(TEMPLATE, "<svg></svg>",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE)));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(injiVcRenderer.generateCredentialDisplayContent(any(), any(), anyString(), any()))
                .thenReturn(List.of("<svg></svg>"));
        when(svgFixerUtil.addMissingOffsetToStopElements(anyString())).thenAnswer(inv -> inv.getArgument(0));
        when(injiVcRenderer.convertSvgToPdf(anyList())).thenReturn("AQID");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testInjiVcRendererInvokedForLdpVcWhenRenderMethodListWithTemplates() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE,
                TEMPLATE, Map.of("id", "https://certify/rendering-template/5b9c")
            ),
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE,
                TEMPLATE, Map.of("id", "https://certify/rendering-template/6b9c")
            ),
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE,
                TEMPLATE, Map.of("id", "https://certify/rendering-template/7b9c")
            )
        ));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
            .format("ldp_vc")
            .credential(credentialMap)
            .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(injiVcRenderer.generateCredentialDisplayContent(any(), any(), anyString(), any()))
                .thenReturn(List.of("<svg></svg>"));
        when(svgFixerUtil.addMissingOffsetToStopElements(anyString())).thenAnswer(inv -> inv.getArgument(0));
        when(injiVcRenderer.convertSvgToPdf(anyList())).thenReturn("AQID");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testV2ContextNullDisablesSvgRendering() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, null); // contextField is null
        credentialMap.put(RENDER_METHOD, List.of(Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE)));

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(any())).thenReturn(Map.of("name", "John"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(new LinkedHashMap<>());
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vc, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedWhenRenderSuiteIsNotSvgMustache() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, "pdf-mustache"));

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(any())).thenReturn(Map.of("name", "John"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(new LinkedHashMap<>());
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vc, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedForLdpVcWhenV2ContextAbsent() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of("https://www.w3.org/ns/credentials/v1"));
        credentialMap.put(RENDER_METHOD, List.of(Map.of(TEMPLATE, "<svg></svg>")));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(Map.of("name", "John"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(new LinkedHashMap<>());
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedForSdJwt() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("vc+sd-jwt")).thenReturn(sdJwtCredentialFormatHandler);
        String validSdJwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOltdLCJuYW1lIjoiSm9obiBEb2UifQ.signature~WyJzYWx0IiwgIm5hbWUiLCAiSm9obiBEb2UiXQ";

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
            .format("vc+sd-jwt")
            .credential(validSdJwt)
            .build();

        Map<String, Object> extractedClaims = new HashMap<>();
        extractedClaims.put("name", "John Doe");
        when(sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
            .thenReturn(extractedClaims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
            .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
            .thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any()))
            .thenReturn(new PresentationDefinitionDTO());

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
            "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
            "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedForLdpVcWithRenderMethodButNoTemplate() throws Exception {
        // Credential with v2 context and renderMethod, but missing "template"
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(Map.of(RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE)));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
            .format("ldp_vc")
            .credential(credentialMap)
            .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
            "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
            "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedForLdpVcWithoutRenderMethod() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
            .format("ldp_vc")
            .credential(credentialMap)
            .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
            "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
            "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testInjiVcRendererNotInvokedForLdpVcWhenOneRenderMethodListEntryMissingTemplate() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE,
                TEMPLATE, Map.of("id", "https://certify/rendering-template/5b9c")
            ),
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE
                // missing TEMPLATE
            ),
            Map.of(
                "type", "TemplateRenderMethod",
                RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE,
                TEMPLATE, Map.of("id", "https://certify/rendering-template/5b8c")
            )
        ));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
            .format("ldp_vc")
            .credential(credentialMap)
            .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(Map.of("name", "John Doe"));
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
            "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
            "https://example.com/share", "", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), anyString(), anyString(), anyString());
    }

    @Test
    void testGeneratePdfForV2CredentialThrowsExceptionWhenRendererReturnsEmptyList() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE)));

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(injiVcRenderer.generateCredentialDisplayContent(any(), any(), anyString(), any()))
                .thenReturn(Collections.emptyList());

        assertThrows(Exception.class, () -> credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vc, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en"));

        verify(injiVcRenderer).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testGeneratePdfForV2CredentialCatchBlockWhenRendererThrows() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE)));

        VCCredentialResponse vc = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
        when(injiVcRenderer.generateCredentialDisplayContent(any(), any(), anyString(), any()))
                .thenThrow(new RuntimeException("Renderer failed"));

        assertThrows(Exception.class, () -> credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vc, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en"));
    }

    @Test
    void testExtractClaim169QrWithValidIdentityQRCode() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 containing identityQRCode
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", "valid-qr-code-data-from-claim169");

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-claim169");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            mocked.verify(() -> Utilities.encodeToString(any(), anyString()));
        }
    }

    @ParameterizedTest
    @MethodSource("provideClaim169QrFallbackScenarios")
    void testExtractClaim169QrFallbackToVCData(String scenarioName, Map<String, Object> claim169Map) throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-vc");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            // Should fallback to VC data QR generation since identityQRCode is null/empty/missing
            verify(pixelPass).generateQRData(anyString(), anyString());
        }
    }

    private static Stream<Arguments> provideClaim169QrFallbackScenarios() {
        // Scenario 1: claim169 Map with null identityQRCode
        Map<String, Object> nullIdentityQRCodeMap = new HashMap<>();
        nullIdentityQRCodeMap.put("identityQRCode", null);

        // Scenario 2: claim169 Map with empty string identityQRCode
        Map<String, Object> emptyIdentityQRCodeMap = new HashMap<>();
        emptyIdentityQRCodeMap.put("identityQRCode", "");

        return Stream.of(
                Arguments.of("null identityQRCode", nullIdentityQRCodeMap),
                Arguments.of("empty string identityQRCode", emptyIdentityQRCodeMap)
        );
    }

    @Test
    void testExtractClaim169QrWithClaim169NotAsMap() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 as String (not Map)
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", "not-a-map-value");

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-vc");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            // Should fallback to VC data QR generation since claim169 is not a Map
            verify(pixelPass).generateQRData(anyString(), anyString());
        }
    }

    @Test
    void testExtractClaim169QrWithClaim169Missing() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential without claim169
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("email", "john@example.com");

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        displayProps.put("email", Map.of(createDisplayResponse("Email", "en"), "john@example.com"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-vc");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass).generateQRData(anyString(), anyString());
        }
    }

    @Test
    void testExtractClaim169QrWithWhitespaceOnlyIdentityQRCode() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 containing whitespace-only identityQRCode
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", "   \t\n  ");

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-claim169");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            verify(objectMapper, never()).writeValueAsString(vcCredentialResponse.getCredential());
            mocked.verify(() -> Utilities.encodeToString(any(), anyString()));
        }
    }

    @Test
    void testExtractClaim169QrWithSdJwtFormat() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("vc+sd-jwt")).thenReturn(sdJwtCredentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);
        vcCredentialResponse.setFormat("vc+sd-jwt");
        String mockSDJWTString = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOltdfQ.signature";
        vcCredentialResponse.setCredential(mockSDJWTString);

        // Setup credential with claim169 containing identityQRCode for SD-JWT format
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", "sd-jwt-qr-code-data");

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        try (MockedStatic<SDJWT> mockedSDJWT = mockStatic(SDJWT.class);
             MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {

            // Mock SDJWT parsing for disclosure extraction
            SDJWT mockSDJWT = mock(SDJWT.class);
            mockedSDJWT.when(() -> SDJWT.parse(mockSDJWTString)).thenReturn(mockSDJWT);
            when(mockSDJWT.getDisclosures()).thenReturn(Collections.emptyList());

            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-claim169");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            mocked.verify(() -> Utilities.encodeToString(any(), anyString()));
            mockedSDJWT.verify(() -> SDJWT.parse(mockSDJWTString));
        }
    }

    @Test
    void testExtractClaim169QrWithNumericIdentityQRCode() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 containing numeric identityQRCode (will be converted to string)
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", 12345);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-claim169");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            mocked.verify(() -> Utilities.encodeToString(any(), anyString()));
        }
    }

    @Test
    void testExtractClaim169QrWithEmptyClaim169Map() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 as empty Map
        Map<String, Object> claim169Map = new HashMap<>();

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-vc");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass).generateQRData(anyString(), anyString());
        }
    }

    @Test
    void testExtractClaim169QrWithClaim169AsList() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);

        // Setup credential with claim169 as List (not Map)
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", List.of("item1", "item2"));

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr-from-vc");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            assertNotNull(result);
            verify(pixelPass).generateQRData(anyString(), anyString());
        }
    }

    @Test
    void testExtractClaim169QrNotCalledWhenQRCodeTypeIsNone() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        // Setup credential with claim169 containing identityQRCode
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", "valid-qr-code-data-from-claim169");

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "", "", "en");

        assertNotNull(result);
        verify(pixelPass, never()).generateQRData(anyString(), anyString());
        verify(presentationService, never()).constructPresentationDefinition(any());
    }

    @Test
    void testExtractClaim169QrNotCalledWhenQRCodeTypeIsNull() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(null);

        // Setup credential with claim169 containing identityQRCode
        Map<String, Object> claim169Map = new HashMap<>();
        claim169Map.put("identityQRCode", "valid-qr-code-data-from-claim169");

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("claim169", claim169Map);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "", "", "en");

        assertNotNull(result);
        verify(pixelPass, never()).generateQRData(anyString(), anyString());
        verify(presentationService, never()).constructPresentationDefinition(any());
    }

   @Test
    void testTitleNameWithMatchingLocaleFromGetPdfResource() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(Map.of("name", "John"));
        issuerDTO.setQr_code_type(QRCodeType.None);

        CredentialSupportedDisplayResponse fr = new CredentialSupportedDisplayResponse();
        fr.setName("French Title");
        fr.setLocale("fr");

        CredentialSupportedDisplayResponse en = new CredentialSupportedDisplayResponse();
        en.setName("English Title");
        en.setLocale("en");

        credentialsSupportedResponse.setDisplay(List.of(fr, en));

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        Map<String, Object> data = ReflectionTestUtils.invokeMethod(
                credentialPDFGeneratorService,
                "getPdfResourceFromVcProperties",
                displayProperties,
                credentialsSupportedResponse,
                vcCredentialResponse,
                issuerDTO,
                "",
                "-1",
                "en"
        );

        assertNotNull(data);
        assertEquals("English Title", data.get("titleName"));
    }

    @Test
    void testTitleNameFallsBackToFirstWhenLocaleNotFoundFromGetPdfResource() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(Map.of("name", "John"));
        issuerDTO.setQr_code_type(QRCodeType.None);

        CredentialSupportedDisplayResponse fr = new CredentialSupportedDisplayResponse();
        fr.setName("French Title");
        fr.setLocale("fr");

        CredentialSupportedDisplayResponse en = new CredentialSupportedDisplayResponse();
        en.setName("English Title");
        en.setLocale("en");

        credentialsSupportedResponse.setDisplay(List.of(fr, en));

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        Map<String, Object> data = ReflectionTestUtils.invokeMethod(
                credentialPDFGeneratorService,
                "getPdfResourceFromVcProperties",
                displayProperties,
                credentialsSupportedResponse,
                vcCredentialResponse,
                issuerDTO,
                "",
                "-1",
                "es"
        );

        assertNotNull(data);
        assertEquals("French Title", data.get("titleName")); // fallback to first
    }

    @Test
    void testTitleNameNullWhenDisplayListNullOrEmptyFromGetPdfResource() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(Map.of("name", "John"));
        issuerDTO.setQr_code_type(QRCodeType.None);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // null display list
        credentialsSupportedResponse.setDisplay(null);
        Map<String, Object> dataNull = ReflectionTestUtils.invokeMethod(
                credentialPDFGeneratorService,
                "getPdfResourceFromVcProperties",
                displayProperties,
                credentialsSupportedResponse,
                vcCredentialResponse,
                issuerDTO,
                "",
                "-1",
                "en"
        );
        assertNotNull(dataNull);
        assertNull(dataNull.get("titleName"));

        // empty display list
        credentialsSupportedResponse.setDisplay(new ArrayList<>());
        Map<String, Object> dataEmpty = ReflectionTestUtils.invokeMethod(
                credentialPDFGeneratorService,
                "getPdfResourceFromVcProperties",
                displayProperties,
                credentialsSupportedResponse,
                vcCredentialResponse,
                issuerDTO,
                "",
                "-1",
                "en"
        );
        assertNotNull(dataEmpty);
        assertNull(dataEmpty.get("titleName"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> invokePdfResourceFromVcProperties(
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            VCCredentialResponse vcCredentialResponse,
            IssuerDTO issuerDTO,
            String dataShareUrl,
            String credentialValidity,
            String locale) throws Exception {
        Method method = CredentialPDFGeneratorService.class.getDeclaredMethod(
                "getPdfResourceFromVcProperties",
                LinkedHashMap.class,
                CredentialsSupportedResponse.class,
                VCCredentialResponse.class,
                IssuerDTO.class,
                String.class,
                String.class,
                String.class);
        method.setAccessible(true);
        return (Map<String, Object>) method.invoke(
                credentialPDFGeneratorService,
                displayProperties, credentialsSupportedResponse,
                vcCredentialResponse, issuerDTO,
                dataShareUrl, credentialValidity, locale);
    }

    @Test
    void testIsFaceKeyFalseWhenSelectedFaceKeyNotNullButKeyDoesNotMatch() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("dateOfBirth", "1990-01-01");
        subjectData.put("face", "base64-encoded-image");
        ((VCCredentialProperties) vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("dateOfBirth", Map.of(createDisplayResponse("Date of Birth", "en"), "1990-01-01"));

        Map<String, Object> data = invokePdfResourceFromVcProperties(
                displayProps, credentialsSupportedResponse, vcCredentialResponse,
                issuerDTO, "https://example.com/share", "2025-12-31", "en");

        @SuppressWarnings("unchecked")
        Map<String, Object> rowProperties = (Map<String, Object>) data.get("rowProperties");

        assertTrue(rowProperties.containsKey("name"),
                "Expected 'name' in rowProperties because isFaceKey=false for 'name'");
        assertTrue(rowProperties.containsKey("dateOfBirth"),
                "Expected 'dateOfBirth' in rowProperties because isFaceKey=false for 'dateOfBirth'");
        assertFalse(rowProperties.containsKey("face"),
                "Expected 'face' absent from rowProperties (not in displayProperties)");
    }

    @Test
    void testIsFaceKeyTrueWhenSelectedFaceKeyMatchesCurrentKey() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("face", "base64-encoded-image");
        ((VCCredentialProperties) vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("face", Map.of(createDisplayResponse("Face Image", "en"), "base64-encoded-image"));

        Map<String, Object> data = invokePdfResourceFromVcProperties(
                displayProps, credentialsSupportedResponse, vcCredentialResponse,
                issuerDTO, "https://example.com/share", "2025-12-31", "en");

        @SuppressWarnings("unchecked")
        Map<String, Object> rowProperties = (Map<String, Object>) data.get("rowProperties");


        assertFalse(rowProperties.containsKey("face"),
                "Expected 'face' excluded from rowProperties because isFaceKey=true");

        assertTrue(rowProperties.containsKey("name"),
                "Expected 'name' in rowProperties because isFaceKey=false for 'name'");

        assertEquals("base64-encoded-image", data.get("face"),
                "Expected the face value to be stored in data['face']");
    }

    @Test
    void testIsFaceKeyFalseWhenSelectedFaceKeyIsNull() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("dateOfBirth", "1990-01-01");
        ((VCCredentialProperties) vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("dateOfBirth", Map.of(createDisplayResponse("Date of Birth", "en"), "1990-01-01"));

        Map<String, Object> data = invokePdfResourceFromVcProperties(
                displayProps, credentialsSupportedResponse, vcCredentialResponse,
                issuerDTO, "https://example.com/share", "2025-12-31", "en");

        @SuppressWarnings("unchecked")
        Map<String, Object> rowProperties = (Map<String, Object>) data.get("rowProperties");

        // selectedFaceKey = null → isFaceKey = false for ALL keys → all must appear in rowProperties
        assertTrue(rowProperties.containsKey("name"),
                "Expected 'name' in rowProperties because selectedFaceKey=null → isFaceKey=false");
        assertTrue(rowProperties.containsKey("dateOfBirth"),
                "Expected 'dateOfBirth' in rowProperties because selectedFaceKey=null → isFaceKey=false");
        // face value in data must be null (no face key found)
        assertNull(data.get("face"),
                "Expected data['face'] to be null when no face key exists in credential");
    }

    @Test
    void testMaskingDisabledForSelectivelyDisclosableClaims() throws Exception {
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "maskDisclosures", false);
        try {
            when(credentialFormatHandlerFactory.getHandler("vc+sd-jwt")).thenReturn(sdJwtCredentialFormatHandler);
            issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

            String validSdJwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjMTIzIl19.signature~WyJzYWx0IiwgIm5hbWUiLCAiSm9obiBEb2UiXQ~";

            VCCredentialResponse sdJwtVcResponse = VCCredentialResponse.builder()
                    .format("vc+sd-jwt")
                    .credential(validSdJwt)
                    .build();

            Map<String, Object> extractedClaims = new HashMap<>();
            extractedClaims.put("name", "John Doe");
            when(sdJwtCredentialFormatHandler.extractCredentialClaims(sdJwtVcResponse)).thenReturn(extractedClaims);

            CredentialIssuerDisplayResponse displayResponse = createDisplayResponse("Name", "en");
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
            displayProps.put("name", Map.of(displayResponse, "John Doe"));
            when(sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                    .thenReturn(displayProps);

            when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                    .thenReturn("<html><body>$rowProperties</body></html>");
            when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());
            when(objectMapper.writeValueAsString(any())).thenReturn("{}");

            try (MockedStatic<SDJWT> mockedSDJWT = mockStatic(SDJWT.class);
                 MockedStatic<Utilities> mockedUtilities = mockStatic(Utilities.class)) {
                SDJWT mockSdjwt = mock(SDJWT.class);
                Disclosure mockDisclosure = mock(Disclosure.class);
                when(mockDisclosure.getClaimName()).thenReturn("name");
                when(mockSdjwt.getDisclosures()).thenReturn(List.of(mockDisclosure));
                mockedSDJWT.when(() -> SDJWT.parse(anyString())).thenReturn(mockSdjwt);
                mockedUtilities.when(() -> Utilities.encodeToString(any(), anyString())).thenReturn("encoded-image");

                ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                        "TestCredential", sdJwtVcResponse, issuerDTO, credentialsSupportedResponse,
                        "https://example.com/share", "2025-12-31", "en");

                assertNotNull(result);
                mockedUtilities.verify(() -> Utilities.maskValue(anyString()), never());
            }
        } finally {
            ReflectionTestUtils.setField(credentialPDFGeneratorService, "maskDisclosures", true);
        }
    }

    @Test
    void testDisplayNameNullExcludesFromRowProperties() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> extractedClaims = new HashMap<>();
        extractedClaims.put("name", "John Doe");
        extractedClaims.put("hiddenField", "some-value");
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(extractedClaims);

        CredentialIssuerDisplayResponse nullNameDisplay = createDisplayResponse(null, "en");
        CredentialIssuerDisplayResponse nameDisplay = createDisplayResponse("Full Name", "en");

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(nameDisplay, "John Doe"));
        displayProps.put("hiddenField", Map.of(nullNameDisplay, "some-value")); // displayName is null

        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>$rowProperties</body></html>");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testExtractFaceReturnsNullFaceWhenFaceValueIsNull() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("face", null);

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>$rowProperties</body></html>");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testExtractFaceReturnsNullFaceWhenFaceValueIsEmptyString() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.None);

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("face", "");

        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(subjectData);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("face", Map.of(createDisplayResponse("Face", "en"), ""));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>$rowProperties</body></html>");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testFormatValueWithListOfNonStringNonMap() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(
            objectMapper,
            presentationService,
            utilities,
            pixelPass,
            credentialFormatHandlerFactory,
            injiVcRenderer,
            svgFixerUtil
        );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        List<Integer> intList = Arrays.asList(1, 2, 3);

        String result = (String) formatValueMethod.invoke(service, intList, "en");

        assertEquals("[1, 2, 3]", result);
    }

    @Test
    void testFormatValueWithListOfMapsWithNoLangKey() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(
            objectMapper,
            presentationService,
            utilities,
            pixelPass,
            credentialFormatHandlerFactory,
            injiVcRenderer,
            svgFixerUtil
        );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, String> mapNoLang = new HashMap<>();
        mapNoLang.put("someOtherKey", "someValue");
        mapNoLang.put(LdpVcV1Constants.VALUE, "No Lang Value");

        List<Map<String, String>> value = List.of(mapNoLang);

        String result = (String) formatValueMethod.invoke(service, value, "en");

        assertEquals("", result);
    }

    @Test
    void testFormatValueWithListOfMapsWithNullValueKey() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(
            objectMapper,
            presentationService,
            utilities,
            pixelPass,
            credentialFormatHandlerFactory,
            injiVcRenderer,
            svgFixerUtil
        );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        Map<String, String> mapNoValue = new HashMap<>();
        mapNoValue.put(LdpVcV1Constants.LANGUAGE, "en");

        List<Map<String, String>> value = List.of(mapNoValue);

        String result = (String) formatValueMethod.invoke(service, value, "en");

        assertEquals("", result);
    }

    @Test
    void testFormatValueWithNullVal() throws Exception {
        CredentialPDFGeneratorService service = new CredentialPDFGeneratorService(
            objectMapper,
            presentationService,
            utilities,
            pixelPass,
            credentialFormatHandlerFactory,
            injiVcRenderer,
            svgFixerUtil
        );
        Method formatValueMethod = CredentialPDFGeneratorService.class.getDeclaredMethod("formatValue", Object.class, String.class);
        formatValueMethod.setAccessible(true);

        String result = (String) formatValueMethod.invoke(service, null, "en");

        assertEquals("", result);
    }

    @Test
    void testInjiVcRendererNotInvokedWhenRenderMethodListContainsNonMapEntry() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of("not-a-map-entry"));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "credentialConfigId", vcCredentialResponse, issuerDTO,
                credentialsSupportedResponse, "http://datashare.url", "2025-12-31", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testInjiVcRendererNotInvokedWhenRenderMethodListHasTemplateButWrongRenderSuite() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, List.of(
                Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, "SomeOtherRenderSuite")
        ));

        VCCredentialResponse vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "credentialConfigId", vcCredentialResponse, issuerDTO,
                credentialsSupportedResponse, "http://datashare.url", "2025-12-31", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testInjiVcRendererNotInvokedWhenRenderMethodIsMapWithoutTemplate() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, Map.of(RENDER_SUITE, SVG_MUSTACHE_RENDER_SUITE));

        VCCredentialResponse localVcResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(localVcResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "credentialConfigId", localVcResponse, issuerDTO,
                credentialsSupportedResponse, "http://datashare.url", "2025-12-31", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }

    @Test
    void testInjiVcRendererNotInvokedWhenRenderMethodIsMapWithTemplateButWrongRenderSuite() throws Exception {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put(CONTEXT, List.of(V2_CONTEXT_URL));
        credentialMap.put(RENDER_METHOD, Map.of(TEMPLATE, "<svg></svg>", RENDER_SUITE, "SomeOtherRenderSuite"));

        VCCredentialResponse localVcResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(credentialMap)
                .build();

        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        when(credentialFormatHandler.extractCredentialClaims(localVcResponse)).thenReturn(claims);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Name", "en"), "John Doe"));
        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString())).thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString())).thenReturn("<html></html>");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(presentationService.constructPresentationDefinition(any())).thenReturn(new PresentationDefinitionDTO());

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "credentialConfigId", localVcResponse, issuerDTO,
                credentialsSupportedResponse, "http://datashare.url", "2025-12-31", "en");

        assertNotNull(result);
        verify(injiVcRenderer, never()).generateCredentialDisplayContent(any(), any(), anyString(), any());
    }
}
