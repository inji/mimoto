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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
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

    @Before
    public void setUp() throws JsonProcessingException {
        VerifiersDTO verifiersDTO = TestUtilities.getTrustedVerifiers();
        String verifiersListString = TestUtilities.getObjectAsString(verifiersDTO);
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(verifiersListString);
        when(objectMapper.readValue(eq(verifiersListString), eq(VerifiersDTO.class))).thenReturn(verifiersDTO);
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
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId").responseUri("https://test-responseUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getResponseUri());
    }

    @Test(expected = InvalidVerifierException.class)
    public void validateTrustedVerifiersAndThrowInvalidVerifierExceptionWhenClientIdIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").responseUri("https://test-responseUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getResponseUri());
    }

    @Test
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionForAInvalidClientId() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").responseUri("https://test-responseUri").build();
        String expectedExceptionMsg = "invalid_client --> The requested client doesn’t match.";
        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class, () -> verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getResponseUri()));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionWhenClientIdIsValidAndResponseUriIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId").responseUri("https://test-reponseUri/invalid-uri").build();
        String expectedExceptionMsg = "invalid_response_uri --> The requested response uri doesn’t match.";

        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class, () -> verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getResponseUri()));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void validateVerifierThrowsExceptionWhenResponseUriIsInvalidUrl() throws ApiNotAccessibleException, IOException {
        String expectedExceptionMsg = "invalid_response_uri --> The requested response uri doesn’t match.";

        InvalidVerifierException actualException = assertThrows(InvalidVerifierException.class,
                () -> verifiersService.validateVerifier("test-clientId", "not-a-valid-url"));

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
                () -> verifiersService.validateVerifier("test-clientId", "https://test-responseUri"));

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

    @Test
    public void testIsVerifierClientPreregisteredNullClientId() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?other_param=value";

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredEmptyClientId() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=";

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredWhitespaceOnlyClientId() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=%20%20";

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
    public void testIsVerifierClientPreregisteredNullUrl() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = null;

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredEmptyUrl() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "";

        boolean result = verifiersService.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsVerifierClientPreregisteredWhitespaceOnlyUrl() throws URISyntaxException {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "   ";

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
