package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.repository.VerifierRepository;
import io.mosip.mimoto.service.impl.VerifierServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.Utilities;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class VerifierServiceTest {

    @Mock
    Utilities utilities;
    @Mock
    ObjectMapper objectMapper;
    @InjectMocks
    VerifierServiceImpl verifiersService;

    @Mock
    VerifierRepository verifierRepository;

    private static final String VALID_CLIENT_ID = "https://injiverify.collab.mosip.net";
    private static final String ENCODED_CLIENT_ID = "https%3A%2F%2Finjiverify.collab.mosip.net";
    private static final String VALID_RESPONSE_URI = "https://example.com/callback";
    private static final String ENCODED_RESPONSE_URI = "https%3A%2F%2Fexample.com%2Fcallback";

    @BeforeEach
    public void setUp() throws JsonProcessingException {
        VerifiersDTO verifiersDTO = TestUtilities.getTrustedVerifiers();
        String verifiersListString = TestUtilities.getObjectAsString(verifiersDTO);
        lenient().when(utilities.getTrustedVerifiersJsonValue()).thenReturn(verifiersListString);
        lenient().when(objectMapper.readValue(eq(verifiersListString), eq(VerifiersDTO.class))).thenReturn(verifiersDTO);
    }

    @Test
    public void shouldReturnAllTrustedIssuers() throws ApiNotAccessibleException, JsonProcessingException {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri")).build();
        VerifiersDTO expectedTrustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        VerifiersDTO actualTrustedVerifiers = verifiersService.getTrustedVerifiers();

        assertNotNull(actualTrustedVerifiers);
        assertEquals(actualTrustedVerifiers, expectedTrustedVerifiers);
    }

    @Test
    public void getCorrectVerifierWhenCorrectClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifierByClientId("test-clientId");
        assertNotNull(verifierDTO.get());
        assertEquals(verifierDTO.get().getClientId(), "test-clientId");
    }

    @Test
    public void getNullWhenInvalidClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifierByClientId("test-clientId2");
        assertTrue(verifierDTO.isEmpty());
    }

    @Test
    public void getVerifierByClientIdReturnsRegisteredRedirectUrisForClient() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifier = verifiersService.getVerifierByClientId("test-clientId");

        assertTrue(verifier.isPresent());
        assertEquals(Collections.singletonList("https://test-redirectUri"), verifier.get().getRedirectUris());
    }

    @Test
    public void shouldThrowApiNotAccessibleExceptionOnFetchingTrustedVerifiersListFailure() {
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(null);
        String expectedExceptionMsg = "RESIDENT-APP-026 --> Api not accessible failure";

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> {
            verifiersService.getVerifierByClientId("test-clientId2");
        });

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateTrustedVerifiersAndDoNothing() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId").responseUri("https://test-responseUri").redirectUri("https://test-redirectUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getResponseUri(), presentationRequestDTO.getRedirectUri());
    }

    @Test
    public void validateVerifier_succeedsWhenResponseUriNullAndRedirectUriMatches() throws ApiNotAccessibleException, IOException {
        verifiersService.validateVerifier("test-clientId", null, "https://test-redirectUri");
    }

    @Test
    public void validateVerifierSucceedsWhenResponseUriEmptyAndRedirectUriMatches() throws ApiNotAccessibleException, IOException {
        verifiersService.validateVerifier("test-clientId", "", "https://test-redirectUri");
    }

    @Test
    public void validateVerifierThrowsInvalidRedirectUriWhenRedirectDoesNotMatchRegistered() throws ApiNotAccessibleException, IOException {
        String expectedMsg = "invalid_redirect_uri --> The requested redirect uri doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", null, "https://other-app.example/callback"));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateVerifierThrowsInvalidRedirectUriWhenRedirectUriIsNotAValidUrl() throws ApiNotAccessibleException, IOException {
        String expectedMsg = "invalid_redirect_uri --> The requested redirect uri doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", null, "not-a-valid-url"));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateVerifierThrowsInvalidRedirectUriWhenRedirectUriNull() throws ApiNotAccessibleException, IOException {
        String expectedMsg = "invalid_redirect_uri --> The requested redirect uri doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", null, null));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateVerifierThrowsInvalidClientWhenClientNotFoundAndResponseUriSkippedForRedirectValidation() throws ApiNotAccessibleException, IOException {
        String expectedMsg = "invalid_client --> The requested client doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("unknown-client-id", null, "https://test-redirectUri"));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateVerifierThrowsInvalidRedirectUriWhenRegisteredRedirectUriIsNotAValidUrl() throws Exception {
        VerifierDTO verifier = VerifierDTO.builder()
                .clientId("client-with-bad-registered-redirect")
                .redirectUris(Collections.singletonList("not-a-valid-registered-redirect-uri"))
                .responseUris(Collections.singletonList("https://cb.example/resp"))
                .build();
        VerifiersDTO dto = VerifiersDTO.builder().verifiers(Collections.singletonList(verifier)).build();
        String json = new ObjectMapper().writeValueAsString(dto);
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(json);
        when(objectMapper.readValue(anyString(), eq(VerifiersDTO.class))).thenReturn(dto);

        String expectedMsg = "invalid_redirect_uri --> The requested redirect uri doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("client-with-bad-registered-redirect", null,
                        "https://valid-redirect.example/callback"));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateVerifierThrowsInvalidRedirectUriWhenRegisteredRedirectValidButPathDoesNotMatch() throws ApiNotAccessibleException, IOException {
        String expectedMsg = "invalid_redirect_uri --> The requested redirect uri doesn’t match.";

        InvalidVerifierException ex = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", null,
                        "https://test-redirectUri/extra-path"));

        assertEquals(expectedMsg, ex.getMessage());
    }

    @Test
    public void validateTrustedVerifiersAndThrowInvalidVerifierExceptionWhenClientIdIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").responseUri("https://test-responseUri").build();
        String clientId = presentationRequestDTO.getClientId();
        String responseUri = presentationRequestDTO.getResponseUri();
        String redirectUri = presentationRequestDTO.getRedirectUri();
        assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier(clientId, responseUri, redirectUri));
    }

    @Test
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionForAInvalidClientId() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").responseUri("https://test-responseUri").build();
        String expectedExceptionMsg = "invalid_client --> The requested client doesn’t match.";
        String clientId = presentationRequestDTO.getClientId();
        String responseUri = presentationRequestDTO.getResponseUri();
        String redirectUri = presentationRequestDTO.getRedirectUri();
        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier(clientId, responseUri, redirectUri));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionWhenClientIdIsValidAndResponseUriIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId").responseUri("https://test-reponseUri/invalid-uri").build();
        String expectedExceptionMsg = "invalid_response_uri --> The requested response uri doesn’t match.";
        String clientId = presentationRequestDTO.getClientId();
        String responseUri = presentationRequestDTO.getResponseUri();
        String redirectUri = presentationRequestDTO.getRedirectUri();
        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier(clientId, responseUri, redirectUri));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateVerifierThrowsExceptionWhenResponseUriIsInvalidUrl() throws ApiNotAccessibleException, IOException {
        String expectedExceptionMsg = "invalid_response_uri --> The requested response uri doesn’t match.";

        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", "not-a-valid-url", ""));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateVerifierThrowsExceptionWhenRegisteredResponseUriIsInvalidUrl() throws Exception {
        VerifierDTO verifierWithBadUri = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("not-a-valid-registered-uri")).build();
        VerifiersDTO verifiersWithBadUri = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierWithBadUri)).build();

        String json = new ObjectMapper().writeValueAsString(verifiersWithBadUri);
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(json);
        when(objectMapper.readValue(eq(json), eq(VerifiersDTO.class))).thenReturn(verifiersWithBadUri);

        String expectedExceptionMsg = "invalid_response_uri --> The requested response uri doesn’t match.";

        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", "https://test-responseUri", ""));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void testIsVerifierTrustedByWallet_TrustedVerifier() {
        String walletId = "wallet123";
        String verifierId = "verifier123";
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, verifierId)).thenReturn(true);

        boolean result = verifiersService.isVerifierTrustedByWallet(verifierId, walletId);

        assertTrue(result);
    }

    @Test
    public void testIsVerifierTrustedByWallet_UntrustedVerifier() {
        String walletId = "wallet123";
        String verifierId = "verifier123";
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, verifierId)).thenReturn(false);

        boolean result = verifiersService.isVerifierTrustedByWallet(verifierId, walletId);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierTrustedByWallet_NullInputs() {
        String walletId = null;
        String verifierId = null;
        when(verifierRepository.existsByWalletIdAndVerifierId(walletId, verifierId)).thenReturn(false);

        boolean result = verifiersService.isVerifierTrustedByWallet(verifierId, walletId);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredValidClientIdAndMatchingVerifier() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredValidClientIdButNoMatchingVerifier() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier("https://other-verifier.com", List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "https://example.com?other_param=value", "https://example.com?client_id=", "https://example.com?client_id=%20%20"})
    public void isVerifierClientPreregisteredReturnsFalseForBlankOrMissingClientId(String url) throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredEmptyVerifiersList() throws URISyntaxException {
        List<Verifier> verifiers = Collections.emptyList();
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredPartialResponseUrisMatch() throws URISyntaxException {
        List<String> verifierResponseUris = Arrays.asList("https://example.com/callback1", "https://example.com/callback2");
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, verifierResponseUris, null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredSpecialCharactersInClientId() throws URISyntaxException {
        String specialClientId = "https://test.com/path?param=value&other=123";
        String encodedSpecialClientId = "https%3A%2F%2Ftest.com%2Fpath%3Fparam%3Dvalue%26other%3D123";
        List<Verifier> verifiers = List.of(new Verifier(specialClientId, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + encodedSpecialClientId;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredSpecialCharactersInResponseUri() throws URISyntaxException {
        String specialResponseUri = "https://test.com/callback?param=value&other=123";
        String encodedSpecialResponseUri = "https%3A%2F%2Ftest.com%2Fcallback%3Fparam%3Dvalue%26other%3D123";
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(specialResponseUri), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + encodedSpecialResponseUri;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredMultipleVerifiers() throws URISyntaxException {
        List<Verifier> verifiers = Arrays.asList(new Verifier("https://verifier1.com", List.of("https://callback1.com"), null), new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null), new Verifier("https://verifier3.com", List.of("https://callback3.com"), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredNullResponseUris() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredEmptyResponseUris() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=";

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }
}
