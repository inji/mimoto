package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.impl.MsoMdocCredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.pixelpass.PixelPass;
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
class MsoMdocCredentialFormatHandlerTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private PixelPass pixelPass;

    @InjectMocks
    private MsoMdocCredentialFormatHandler handler;

    private VCCredentialResponse vcCredentialResponse;
    private CredentialsSupportedResponse credentialsSupportedResponse;

    @BeforeEach
    void setUp() {
        vcCredentialResponse = new VCCredentialResponse();
        credentialsSupportedResponse = new CredentialsSupportedResponse();
    }

    // getSupportedFormat
    @Test
    void getSupportedFormatShouldReturnMsoMdoc() {
        assertEquals(CredentialFormat.MSO_MDOC.getFormat(), handler.getSupportedFormat());
    }

    // extractCredentialClaims
    @Test
    void extractCredentialClaimsWithNonStringCredentialShouldReturnEmptyMap() {
        vcCredentialResponse.setCredential(new Object());

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWhenPixelPassReturnsNullShouldReturnEmptyMap() {
        vcCredentialResponse.setCredential("someCborBase64");
        when(pixelPass.toJson("someCborBase64")).thenReturn(null);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWhenPixelPassThrowsShouldReturnEmptyMap() {
        vcCredentialResponse.setCredential("invalidCbor");
        when(pixelPass.toJson("invalidCbor")).thenThrow(new RuntimeException("Decode failed"));

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWithValidCborUnderIssuerSignedShouldReturnFlattenedClaims() throws Exception {
        vcCredentialResponse.setCredential("validCborBase64");

        Map<String, Object> givenNameItem = Map.of("elementIdentifier", "given_name", "elementValue", "John");
        Map<String, Object> familyNameItem = Map.of("elementIdentifier", "family_name", "elementValue", "Doe");
        Map<String, Object> nameSpaces = Map.of("org.iso.18013.5.1", List.of(givenNameItem, familyNameItem));
        Map<String, Object> issuerSigned = Map.of("nameSpaces", nameSpaces, "issuerAuth", "auth");
        Map<String, Object> root = Map.of("issuerSigned", issuerSigned);

        when(pixelPass.toJson("validCborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("John", result.get("given_name"));
        assertEquals("Doe", result.get("family_name"));
    }

    @Test
    void extractCredentialClaimsWithNameSpacesAtTopLevelShouldReturnFlattenedClaims() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");

        Map<String, Object> item = Map.of("elementIdentifier", "document_number", "elementValue", "DL123");
        Map<String, Object> nameSpaces = Map.of("org.iso.18013.5.1", List.of(item));
        Map<String, Object> root = new HashMap<>();
        root.put("nameSpaces", nameSpaces);

        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertEquals("DL123", result.get("document_number"));
    }

    @Test
    void extractCredentialClaimsWhenNameSpacesNotAMapShouldReturnEmptyMap() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");

        Map<String, Object> root = new HashMap<>();
        root.put("nameSpaces", "not-a-map");

        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWhenItemMissingElementIdentifierShouldSkipItem() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");

        Map<String, Object> itemWithoutId = Map.of("elementValue", "someValue");
        Map<String, Object> validItem = Map.of("elementIdentifier", "given_name", "elementValue", "John");
        Map<String, Object> nameSpaces = Map.of("org.iso.18013.5.1", List.of(itemWithoutId, validItem));
        Map<String, Object> root = Map.of("nameSpaces", nameSpaces);

        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("John", result.get("given_name"));
    }

    @Test
    void extractCredentialClaimsWithMultipleNamespacesShouldMergeAllItems() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");

        Map<String, Object> item1 = Map.of("elementIdentifier", "given_name", "elementValue", "Jane");
        Map<String, Object> item2 = Map.of("elementIdentifier", "age_over_18", "elementValue", true);

        Map<String, Object> nameSpaces = new LinkedHashMap<>();
        nameSpaces.put("org.iso.18013.5.1", List.of(item1));
        nameSpaces.put("org.iso.18013.5.1.aamva", List.of(item2));
        Map<String, Object> root = Map.of("nameSpaces", nameSpaces);

        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("Jane", result.get("given_name"));
        assertEquals(true, result.get("age_over_18"));
    }

    @Test
    void extractCredentialClaimsWhenObjectMapperThrowsShouldReturnEmptyMap() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");
        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class)))
                .thenThrow(new RuntimeException("JSON parse error"));

        Map<String, Object> result = handler.extractCredentialClaims(vcCredentialResponse);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    // extractAllCredentialProperties
    @Test
    void extractAllCredentialPropertiesShouldDelegateToExtractCredentialClaims() throws Exception {
        vcCredentialResponse.setCredential("cborBase64");

        Map<String, Object> item = Map.of("elementIdentifier", "given_name", "elementValue", "John");
        Map<String, Object> nameSpaces = Map.of("org.iso.18013.5.1", List.of(item));
        Map<String, Object> root = Map.of("nameSpaces", nameSpaces);

        when(pixelPass.toJson("cborBase64")).thenReturn("{}");
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(root);

        Map<String, ?> result = handler.extractAllCredentialProperties(vcCredentialResponse);

        assertNotNull(result);
        assertEquals("John", result.get("given_name"));
    }

    // loadDisplayPropertiesFromWellknown
    @Test
    void loadDisplayPropertiesFromWellknownWithNullClaimsShouldUseFallbackWithSnakeCaseLabel() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("given_name", "John");
        credentialProperties.put("family_name", "Doe");

        credentialsSupportedResponse.setClaims(null);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("given_name"));

        CredentialIssuerDisplayResponse display = result.get("given_name").keySet().iterator().next();
        assertEquals("Given Name", display.getName());
        assertEquals("en", display.getLocale());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithEmptyClaimsShouldUseFallback() {
        Map<String, Object> credentialProperties = Map.of("document_number", "DL123");

        credentialsSupportedResponse.setClaims(new HashMap<>());

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

        assertNotNull(result);
        assertEquals(1, result.size());
        CredentialIssuerDisplayResponse display = result.get("document_number").keySet().iterator().next();
        assertEquals("Document Number", display.getName());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNamespaceNestedClaimsShouldReturnUnwrappedDisplayProperties() {
        Map<String, Object> credentialProperties = Map.of("given_name", "John");

        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("given_name", new HashMap<>());
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));

        CredentialDisplayResponseDto dto = createCredentialDisplayResponseDto("Given Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class))).thenReturn(dto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("given_name"));
            CredentialIssuerDisplayResponse display = result.get("given_name").keySet().iterator().next();
            assertEquals("Given Name", display.getName());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithMultipleNamespacesShouldFlattenAllClaimsForDisplay() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("given_name", "John");
        credentialProperties.put("age_over_18", true);

        // Two namespaces — the bug caused the second namespace's claims to be ignored
        Map<String, Object> isoNsClaims = new HashMap<>();
        isoNsClaims.put("given_name", new HashMap<>());
        Map<String, Object> aamvaNsClaims = new HashMap<>();
        aamvaNsClaims.put("age_over_18", new HashMap<>());
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("org.iso.18013.5.1", isoNsClaims);
        claims.put("org.iso.18013.5.1.aamva", aamvaNsClaims);
        credentialsSupportedResponse.setClaims(claims);

        CredentialDisplayResponseDto givenNameDto = createCredentialDisplayResponseDto("Given Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age Over 18", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(givenNameDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("given_name"));
            assertTrue(result.containsKey("age_over_18"));

            CredentialIssuerDisplayResponse ageDisplay = result.get("age_over_18").keySet().iterator().next();
            assertEquals("Age Over 18", ageDisplay.getName());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWhenNullResolvedLocaleShouldUseFallbackLabel() {
        Map<String, Object> credentialProperties = Map.of("given_name", "John");

        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("given_name", new HashMap<>());
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));

        CredentialDisplayResponseDto dto = createCredentialDisplayResponseDto("Given Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class))).thenReturn(dto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("fr"))).thenReturn(null);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "fr");

            assertNotNull(result);
            assertTrue(result.containsKey("given_name"));

            CredentialIssuerDisplayResponse display = result.get("given_name").keySet().iterator().next();
            assertEquals("Given Name", display.getName());
            assertEquals("en", display.getLocale());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithCustomOrderShouldRespectOrder() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("givenName", "John");
        credentialProperties.put("birthDate", "1990-01-01");

        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("givenName", new HashMap<>());
        nsInnerClaims.put("birthDate", new HashMap<>());
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));
        credentialsSupportedResponse.setOrder(List.of("birthDate", "givenName"));

        CredentialDisplayResponseDto dto1 = createCredentialDisplayResponseDto("Given Name", "en");
        CredentialDisplayResponseDto dto2 = createCredentialDisplayResponseDto("Birth Date", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class))).thenReturn(dto1, dto2);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("birthDate", keyOrder.get(0));
            assertEquals("givenName", keyOrder.get(1));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullValueInCredentialPropertiesShouldSkipField() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("givenName", "John");
        credentialProperties.put("portrait", null);

        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("givenName", new HashMap<>());
        nsInnerClaims.put("portrait", new HashMap<>());
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));

        CredentialDisplayResponseDto dto = createCredentialDisplayResponseDto("Given Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class))).thenReturn(dto, dto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("givenName"));
            assertFalse(result.containsKey("portrait"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownFallbackShouldExcludeIdField() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("id", "some-id");
        credentialProperties.put("givenName", "John");

        credentialsSupportedResponse.setClaims(null);

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

        assertNotNull(result);
        assertEquals(1, result.size());
        assertFalse(result.containsKey("id"));
        assertTrue(result.containsKey("givenName"));
    }

    @Test
    void loadDisplayPropertiesFromWellknownWhenKeyNotInLocalizedMapShouldUseFallbackLabel() {
        Map<String, Object> credentialProperties = new LinkedHashMap<>();
        credentialProperties.put("given_name", "John");
        credentialProperties.put("extra_field", "extraValue");

        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("given_name", new HashMap<>());
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));

        CredentialDisplayResponseDto dto = createCredentialDisplayResponseDto("Given Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class))).thenReturn(dto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("extra_field"));

            CredentialIssuerDisplayResponse extraDisplay = result.get("extra_field").keySet().iterator().next();
            assertEquals("Extra Field", extraDisplay.getName());
            assertEquals("en", extraDisplay.getLocale());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithDirectArrayClaimDisplayShouldBuildDtoCorrectly() {
        Map<String, Object> credentialProperties = Map.of("family_name", "Doe");

        CredentialIssuerDisplayResponse displayResponse = new CredentialIssuerDisplayResponse();
        displayResponse.setName("Family Name");
        displayResponse.setLocale("en");
        List<CredentialIssuerDisplayResponse> displayList = List.of(displayResponse);

        // MDL wellknown: claim value is a direct array, not {"display": [...]}
        Map<String, Object> nsInnerClaims = new HashMap<>();
        nsInnerClaims.put("family_name", displayList);
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18013.5.1", nsInnerClaims));

        when(objectMapper.convertValue(any(), any(TypeReference.class))).thenReturn(displayList);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en"))).thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en"))).thenReturn(true);

            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    handler.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, "en");

            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("family_name"));
            CredentialIssuerDisplayResponse display = result.get("family_name").keySet().iterator().next();
            assertEquals("Family Name", display.getName());
            assertEquals("en", display.getLocale());
            // must NOT call convertValue with CredentialDisplayResponseDto.class — that's the Map path
            verify(objectMapper, never()).convertValue(any(), eq(CredentialDisplayResponseDto.class));
        }
    }

    private CredentialDisplayResponseDto createCredentialDisplayResponseDto(String name, String locale) {
        CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
        display.setName(name);
        display.setLocale(locale);
        dto.setDisplay(List.of(display));
        return dto;
    }
}
