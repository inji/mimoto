package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.impl.VcSdJwtCredentialFormatHandler;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.mimoto.util.LocaleUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VcSdJwtCredentialFormatHandlerTest {

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VcSdJwtCredentialFormatHandler vcSdJwtCredentialFormatHandler;

    private VCCredentialResponse vcCredentialResponse;
    private CredentialsSupportedResponse credentialsSupportedResponse;
    private String sampleSdJwtString;
    private String sampleJwtString;

    @BeforeEach
    void setUp() {
        vcCredentialResponse = new VCCredentialResponse();
        credentialsSupportedResponse = new CredentialsSupportedResponse();

        // Sample SD-JWT string (simplified for testing)
        sampleSdJwtString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.invalid";

        // Sample JWT string for payload parsing
        sampleJwtString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.invalid";
    }

    @Test
    void extractCredentialClaimsWithStringCredentialShouldReturnClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            // Mock JWT payload with credentialSubject
            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("name", "John Doe");
            jwtPayload.put("admin", true);
            jwtPayload.put("iss", "https://example.com");
            jwtPayload.put("sub", "1234567890");
            jwtPayload.put("iat", 1516239022);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals(true, result.get("admin"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
            assertFalse(result.containsKey("sub"));
            assertFalse(result.containsKey("iat"));
        }
    }

    @Test
    void extractCredentialClaimsWithoutCredentialSubjectShouldReturnAllClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            // Mock JWT payload without credentialSubject
            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("name", "John Doe");
            jwtPayload.put("admin", true);
            jwtPayload.put("iss", "https://example.com");
            jwtPayload.put("sub", "1234567890");
            jwtPayload.put("iat", 1516239022);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals(true, result.get("admin"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
            assertFalse(result.containsKey("sub"));
            assertFalse(result.containsKey("iat"));
        }
    }

    @Test
    void extractCredentialClaimsWithNonStringCredentialShouldReturnEmptyMap() {
        // Given
        vcCredentialResponse.setCredential(new Object());

        // When
        Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWithInvalidSdJwtShouldReturnEmptyMap() {
        // Given
        vcCredentialResponse.setCredential("invalid-sd-jwt");

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            mockedSdJwt.when(() -> SDJWT.parse("invalid-sd-jwt"))
                    .thenThrow(new IllegalArgumentException("Invalid SD-JWT"));

            // When
            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractCredentialClaimsWithDisclosuresShouldIncludeDisclosedClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            Disclosure mockDisclosure = mock(Disclosure.class);
            List<Disclosure> disclosures = Arrays.asList(mockDisclosure);

            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(disclosures);
            when(mockDisclosure.getClaimName()).thenReturn("disclosedClaim");
            when(mockDisclosure.getClaimValue()).thenReturn("disclosedValue");

            // Mock JWT payload
            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("name", "John Doe");
            jwtPayload.put("iss", "https://example.com");

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals("disclosedValue", result.get("disclosedClaim"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
        }
    }

    @Test
    void extractCredentialClaimsWithNullCredentialJwtShouldHandleGracefully() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(null);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithValidDataShouldReturnDisplayProperties() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("name", "age"));

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("name"));
            assertTrue(result.containsKey("age"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNestedClaimsShouldHandleCorrectly() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("name", new HashMap<>());

        Map<String, Object> wrappedClaims = new HashMap<>();
        wrappedClaims.put("wrapper", nestedClaims);

        credentialsSupportedResponse.setClaims(wrappedClaims);

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("name"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullClaimsShouldUseConvertedLabel() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("UINValue", "12345");

        credentialsSupportedResponse.setClaims(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("firstName"));
        assertTrue(result.containsKey("UINValue"));

        // Check that fallback display for "firstName"
        Map<CredentialIssuerDisplayResponse, Object> displayMap = result.get("firstName");
        CredentialIssuerDisplayResponse display = displayMap.keySet().iterator().next();
        assertEquals("First Name", display.getName()); // convertKeyToLabel should convert camelCase to Pascal Case
        assertEquals("en", display.getLocale());
        assertEquals("John", displayMap.get(display));

        // Check fallback display for "UINValue"
        Map<CredentialIssuerDisplayResponse, Object> uinValueDisplayMap = result.get("UINValue");
        CredentialIssuerDisplayResponse uinValueDisplay = uinValueDisplayMap.keySet().iterator().next();
        assertEquals("UIN Value", uinValueDisplay.getName()); // convertKeyToLabel should convert camelCase to Pascal Case
        assertEquals("en", uinValueDisplay.getLocale());
        assertEquals("12345", uinValueDisplayMap.get(uinValueDisplay));

    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullResolvedLocaleShouldUseConvertedLabel() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John Doe");

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("firstName", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("fr")))
                    .thenReturn(null);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "fr");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("firstName"));

            // Check that fallback display was created
            Map<CredentialIssuerDisplayResponse, Object> displayMap = result.get("firstName");
            CredentialIssuerDisplayResponse display = displayMap.keySet().iterator().next();
            assertEquals("First Name", display.getName());
            assertEquals("en", display.getLocale());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithCustomOrderShouldRespectOrder() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("age", "name")); // Custom order

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("age", keyOrder.get(0));
            assertEquals("name", keyOrder.get(1));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithCustomOrderShouldRespectOrderAndAppendAdditionalFieldsNotPresentInWellknownClaimsAtEnd() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);
        credentialProperties.put("dob", "1990-01-01"); // Additional field not present in well-known claims
        credentialProperties.put("email", "xyz@gmail.com"); // Additional field not present in well-known claims

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("age", "name")); // Custom order

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");
        CredentialDisplayResponseDto dobDto = createCredentialDisplayResponseDto("DOB", "en");
        CredentialDisplayResponseDto emailDto = createCredentialDisplayResponseDto("Email", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, dobDto, emailDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(4, result.size());
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("age", keyOrder.get(0));
            assertEquals("name", keyOrder.get(1));
            assertEquals("dob", keyOrder.get(2)); // Additional field should be appended at the end
            assertEquals("email", keyOrder.get(3)); // Additional field should be appended at the end
        }
    }

    @Test
    void buildCredentialRequestShouldReturnBuiltRequest() {
        // Given
        VCCredentialRequestProof proof = VCCredentialRequestProof.builder()
                .proofType("jwt")
                .jwt("sample.jwt.token")
                .build();

        credentialsSupportedResponse.setVct("IdentityCredential");

        // When
        VCCredentialRequest result = vcSdJwtCredentialFormatHandler.buildCredentialRequest(
                proof, credentialsSupportedResponse);

        // Then
        assertNotNull(result);
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), result.getFormat());
        assertEquals(proof, result.getProof());
        assertEquals("IdentityCredential", result.getVct());
    }

    @Test
    void getSupportedFormatShouldReturnCorrectFormat() {
        // When
        String result = vcSdJwtCredentialFormatHandler.getSupportedFormat();

        // Then
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), result);
    }

    @Test
    void buildFallbackDisplayPropertiesWithOrderedKeysShouldRespectOrder() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", "Doe");
        credentialProperties.put("email", "john@example.com");

        List<String> orderedKeys = Arrays.asList("email", "lastName", "firstName");
        credentialsSupportedResponse.setOrder(orderedKeys);
        credentialsSupportedResponse.setClaims(null); // Trigger fallback

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(3, result.size());

        // Verify order is preserved
        List<String> resultKeys = new ArrayList<>(result.keySet());
        assertEquals("email", resultKeys.get(0));
        assertEquals("lastName", resultKeys.get(1));
        assertEquals("firstName", resultKeys.get(2));
    }

    @Test
    void buildFallbackDisplayPropertiesWithNullValuesShouldSkipFields() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("middleName", null);
        credentialProperties.put("lastName", "Doe");

        credentialsSupportedResponse.setClaims(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(2, result.size()); // middleName should be skipped
        assertTrue(result.containsKey("firstName"));
        assertTrue(result.containsKey("lastName"));
        assertFalse(result.containsKey("middleName"));
    }

    @Test
    void buildFallbackDisplayPropertiesWithIdFieldShouldExcludeIt() {
        // Given
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("id", "12345");
        credentialProperties.put("firstName", "John");

        credentialsSupportedResponse.setClaims(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue(result.containsKey("firstName"));
    }

    @Test
    void buildFallbackDisplayPropertiesWithEmptyClaimsShouldTriggerFallback() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", "Doe");

        credentialsSupportedResponse.setClaims(new HashMap<>()); // Empty claims

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(2, result.size());

        CredentialIssuerDisplayResponse firstNameDisplay = result.get("firstName").keySet().iterator().next();
        assertEquals("First Name", firstNameDisplay.getName());
        assertEquals("en", firstNameDisplay.getLocale());

        CredentialIssuerDisplayResponse lastNameDisplay = result.get("lastName").keySet().iterator().next();
        assertEquals("Last Name", lastNameDisplay.getName());
        assertEquals("en", lastNameDisplay.getLocale());
    }

    // ============================================================
    // Tests for extractAllCredentialProperties
    // ============================================================

    @Test
    void extractAllCredentialPropertiesWhenCredentialIsStringReturnsProperties() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(null);

            Map<String, Object> jwtPayload = new LinkedHashMap<>();
            jwtPayload.put("name", "John");
            jwtPayload.put("iss", "https://example.com");
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(jwtPayload);

            Map<String, Map<String, Object>> result = (Map<String, Map<String, Object>>)
                    vcSdJwtCredentialFormatHandler.extractAllCredentialProperties(vcCredentialResponse);

            assertNotNull(result);
            assertTrue(result.containsKey("publicClaims"));
            assertTrue(result.containsKey("sdClaims"));
            assertEquals("John", result.get("publicClaims").get("name"));
        }
    }

    @Test
    void extractAllCredentialPropertiesWhenCredentialIsNotStringReturnsEmptyMap() {
        vcCredentialResponse.setCredential(new HashMap<>());

        Map<String, ?> result = (Map<String, ?>) vcSdJwtCredentialFormatHandler.extractAllCredentialProperties(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    // ============================================================
    // Tests for extractAllPropertiesFromSdJwt
    // ============================================================

    @Test
    void extractAllPropertiesFromSdJwtWhenIllegalArgExceptionReturnsEmptyMap() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            mockedSdJwt.when(() -> SDJWT.parse("bad-jwt"))
                    .thenThrow(new IllegalArgumentException("Invalid SD-JWT"));

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt("bad-jwt");

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWhenGenericExceptionReturnsEmptyMap() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            mockedSdJwt.when(() -> SDJWT.parse("bad-jwt"))
                    .thenThrow(new RuntimeException("Unexpected"));

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt("bad-jwt");

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWhenNullPayloadReturnsSdClaimsEmpty() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(null);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(null);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.get("publicClaims").isEmpty());
            assertTrue(result.get("sdClaims").isEmpty());
        }
    }

    // ============================================================
    // Tests for resolveDisclosures via extractAllPropertiesFromSdJwt
    // ============================================================

    @Test
    void extractAllPropertiesFromSdJwtWithSdDigestsInPayloadResolvesSdClaims() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.digest()).thenReturn("digest1");
            when(disclosure.getDisclosure()).thenReturn("base64disclosure1");
            when(disclosure.getClaimName()).thenReturn("given_name");
            when(disclosure.getClaimValue()).thenReturn("John");
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("_sd", Arrays.asList("digest1"));
            payload.put("iss", "https://example.com");
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            Map<String, Object> sdClaims = result.get("sdClaims");
            assertTrue(sdClaims.containsKey("given_name"));
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithNullDisclosureForDigestSkipsDigest() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(Collections.emptyList());

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("_sd", Arrays.asList("unknownDigest"));
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.get("sdClaims").isEmpty());
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWhenClaimNameIsSdOrKeySkipsDigest() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure sdDisclosure = mock(Disclosure.class);
            when(sdDisclosure.digest()).thenReturn("digest_sd");
            when(sdDisclosure.getDisclosure()).thenReturn("b64sd");
            when(sdDisclosure.getClaimName()).thenReturn("_sd");

            Disclosure keyDisclosure = mock(Disclosure.class);
            when(keyDisclosure.digest()).thenReturn("digest_key");
            when(keyDisclosure.getDisclosure()).thenReturn("b64key");
            when(keyDisclosure.getClaimName()).thenReturn("...");

            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(sdDisclosure, keyDisclosure));

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("_sd", Arrays.asList("digest_sd", "digest_key"));
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            Map<String, Object> sdClaims = result.get("sdClaims");
            assertFalse(sdClaims.containsKey("_sd"));
            assertFalse(sdClaims.containsKey("..."));
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithNestedMapContainingSdDigestsResolvesNestedPaths() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.digest()).thenReturn("nested_digest");
            when(disclosure.getDisclosure()).thenReturn("b64nested");
            when(disclosure.getClaimName()).thenReturn("city");
            when(disclosure.getClaimValue()).thenReturn("Berlin");
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            Map<String, Object> addressMap = new LinkedHashMap<>();
            addressMap.put("_sd", Arrays.asList("nested_digest"));
            addressMap.put("country", "Germany");

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("address", addressMap);
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            Map<String, Object> sdClaims = result.get("sdClaims");
            assertTrue(sdClaims.containsKey("address.city"));
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithArrayDisclosureResolvesArrayItems() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.digest()).thenReturn("arr_digest");
            when(disclosure.getDisclosure()).thenReturn("b64arr");
            when(disclosure.getClaimValue()).thenReturn("disclosed_item");
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            // Array with a disclosure marker {"...": "arr_digest"} and a regular item
            Map<String, Object> disclosureMarker = new LinkedHashMap<>();
            disclosureMarker.put("...", "arr_digest");

            List<Object> arrayWithDisclosure = new ArrayList<>();
            arrayWithDisclosure.add(disclosureMarker);
            arrayWithDisclosure.add("regular_item");

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("nationalities", arrayWithDisclosure);
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            Map<String, Object> sdClaims = result.get("sdClaims");
            assertTrue(sdClaims.containsKey("nationalities[0]"));
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithArrayDisclosureNotFoundSkipsMarker() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(Collections.emptyList());

            Map<String, Object> disclosureMarker = new LinkedHashMap<>();
            disclosureMarker.put("...", "unknown_digest");

            List<Object> arrayWithDisclosure = new ArrayList<>();
            arrayWithDisclosure.add(disclosureMarker);

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("items", arrayWithDisclosure);
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.get("sdClaims").isEmpty());
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithArrayContainingRegularMapRecursesIntoMap() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.digest()).thenReturn("inner_digest");
            when(disclosure.getDisclosure()).thenReturn("b64inner");
            when(disclosure.getClaimName()).thenReturn("secret");
            when(disclosure.getClaimValue()).thenReturn("value");
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            // Regular map (not a disclosure marker) inside a list, containing _sd
            Map<String, Object> innerMap = new LinkedHashMap<>();
            innerMap.put("_sd", Arrays.asList("inner_digest"));
            innerMap.put("visible", "yes");

            List<Object> listValue = new ArrayList<>();
            listValue.add(innerMap);

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("entries", listValue);
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            Map<String, Object> sdClaims = result.get("sdClaims");
            assertTrue(sdClaims.containsKey("entries[0].secret"));
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWithEmptyPayloadReturnsSdClaimsEmpty() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(null);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(new HashMap<>());

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.get("sdClaims").isEmpty());
        }
    }

    @Test
    void extractAllPropertiesFromSdJwtWhenDisclosureClaimNameNullSkipsDisclosure() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.digest()).thenReturn("digest_null_name");
            when(disclosure.getDisclosure()).thenReturn("b64null");
            when(disclosure.getClaimName()).thenReturn(null);
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("_sd", Arrays.asList("digest_null_name"));
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(payload);

            Map<String, Map<String, Object>> result = vcSdJwtCredentialFormatHandler.extractAllPropertiesFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.get("sdClaims").isEmpty());
        }
    }

    // ============================================================
    // Tests for extractSdClaims uncovered branches (via extractClaimsFromSdJwt)
    // ============================================================

    @Test
    void extractClaimsFromSdJwtWhenDisclosuresNullReturnsPublicClaimsOnly() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(null);

            Map<String, Object> jwtPayload = new LinkedHashMap<>();
            jwtPayload.put("name", "John");
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertEquals("John", result.get("name"));
        }
    }

    @Test
    void extractClaimsFromSdJwtWhenDisclosureClaimNameNullSkipsDisclosure() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.getClaimName()).thenReturn(null);
            when(disclosure.getClaimValue()).thenReturn("someValue");
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            Map<String, Object> jwtPayload = new LinkedHashMap<>();
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertFalse(result.containsValue("someValue"));
        }
    }

    @Test
    void extractClaimsFromSdJwtWhenDisclosureClaimValueNullSkipsDisclosure() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure disclosure = mock(Disclosure.class);
            when(disclosure.getClaimName()).thenReturn("age");
            when(disclosure.getClaimValue()).thenReturn(null);
            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(disclosure));

            Map<String, Object> jwtPayload = new LinkedHashMap<>();
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertFalse(result.containsKey("age"));
        }
    }

    @Test
    void extractClaimsFromSdJwtWhenDisclosureThrowsExceptionSkipsAndContinues() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);

            Disclosure badDisclosure = mock(Disclosure.class);
            when(badDisclosure.getClaimName()).thenThrow(new RuntimeException("decode error"));

            Disclosure goodDisclosure = mock(Disclosure.class);
            when(goodDisclosure.getClaimName()).thenReturn("name");
            when(goodDisclosure.getClaimValue()).thenReturn("Alice");

            when(mockSdJwt.getDisclosures()).thenReturn(Arrays.asList(badDisclosure, goodDisclosure));

            Map<String, Object> jwtPayload = new LinkedHashMap<>();
            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertEquals("Alice", result.get("name"));
        }
    }

    @Test
    void extractClaimsFromSdJwtWhenGenericExceptionReturnsEmptyMap() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            mockedSdJwt.when(() -> SDJWT.parse("crash-jwt"))
                    .thenThrow(new RuntimeException("Unexpected crash"));

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt("crash-jwt");

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractClaimsFromSdJwtWhenJwtPayloadNullReturnsEmptyPublicClaims() {
        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(Collections.emptyList());

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString)).thenReturn(null);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractClaimsFromSdJwt(sampleSdJwtString);

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    // ============================================================
    // Tests for loadDisplayPropertiesFromWellknown uncovered branches
    // ============================================================

    @Test
    void loadDisplayPropertiesFromWellknownWhenValueNullInOrderedKeysSkipsField() {
        // Arrange - credentialProperties has a key with null value
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John");
        credentialProperties.put("address", null);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", new HashMap<>());
        claims.put("address", new HashMap<>());
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("name", "address"));

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto addressDto = createCredentialDisplayResponseDto("Address", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, addressDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("name"));
            assertFalse(result.containsKey("address"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWhenDisplayNullFallsBackToGeneratedDisplay() {
        // Arrange - orderedKeys has a key not in claims config (display not found in localizedDisplayMap)
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John");
        credentialProperties.put("extraField", "extraValue");

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", new HashMap<>());
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("name", "extraField"));

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("extraField"));

            CredentialIssuerDisplayResponse extraDisplay = result.get("extraField").keySet().iterator().next();
            assertEquals("Extra Field", extraDisplay.getName());
            assertEquals("en", extraDisplay.getLocale());
        }
    }

    // Helper methods
    private Map<String, Object> createSampleClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", new HashMap<>());
        claims.put("age", new HashMap<>());
        return claims;
    }

    private CredentialDisplayResponseDto createCredentialDisplayResponseDto(String name, String locale) {
        CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
        display.setName(name);
        display.setLocale(locale);
        dto.setDisplay(Arrays.asList(display));
        return dto;
    }
}