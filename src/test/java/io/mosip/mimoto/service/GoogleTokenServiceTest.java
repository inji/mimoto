package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.model.UserMetadata;
import io.mosip.mimoto.service.impl.GoogleTokenService;
import io.mosip.mimoto.service.impl.SecurityContextManager;
import io.mosip.mimoto.service.impl.SessionManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleTokenServiceTest {

    @Mock
    private TokenDecoder tokenDecoder;

    @Mock
    private UserMetadataService userMetadataService;

    @Mock
    private SecurityContextManager securityContextManager;

    @Mock
    private SessionManager sessionManager;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private GoogleTokenService googleTokenService;

    @Captor
    private ArgumentCaptor<UserMetadataDTO> userMetadataDTOArgumentCaptor;

    @Captor
    private ArgumentCaptor<OAuth2AuthenticationToken> oauth2TokenCaptor;

    private String idToken;
    private String provider;
    private Jwt validJwt;
    private Map<String, Object> claims;

    @BeforeEach
    void setUp() {
        idToken = "dummyIdToken";
        provider = "google";

        // Set expectedIssuer and expectedAudience via constructor injection simulation
        googleTokenService = new GoogleTokenService(tokenDecoder, userMetadataService, securityContextManager, sessionManager, "google-client-id", "https://accounts.google.com");

        claims = new HashMap<>();
        claims.put("email", "test@example.com");
        claims.put("name", "Test User");
        claims.put("picture", "http://example.com/picture.jpg");
        claims.put("sub", "google-subject-id");
        claims.put("iss", "https://accounts.google.com");
        claims.put("aud", "google-client-id");
        claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

        validJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }

    @Test
    void processTokenValidTokenShouldCallDependenciesAndSetSessionAndSecurityContext() throws Exception {
        when(tokenDecoder.decode(idToken)).thenReturn(validJwt);
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/picture.jpg", "test@example.com")).thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(tokenDecoder).decode(idToken);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/picture.jpg", "test@example.com");
        verify(sessionManager).setupSession(eq(request), eq(provider), userMetadataDTOArgumentCaptor.capture(), eq("test-user-id"));
        verify(securityContextManager).setupSecurityContext(oauth2TokenCaptor.capture(), eq(request), eq(response));

        UserMetadataDTO capturedUserMetadata = userMetadataDTOArgumentCaptor.getValue();
        assertEquals("Test User", capturedUserMetadata.getDisplayName());
        assertEquals("http://example.com/picture.jpg", capturedUserMetadata.getProfilePictureUrl());
        assertEquals("test@example.com", capturedUserMetadata.getEmail());

        OAuth2AuthenticationToken capturedToken = oauth2TokenCaptor.getValue();
        assertEquals(provider, capturedToken.getAuthorizedClientRegistrationId());
        assertEquals("google-subject-id", capturedToken.getPrincipal().getAttribute("sub"));
    }

    @Test
    void processTokenInvalidIssuerShouldThrowException() throws OAuth2AuthenticationException {
        Jwt invalidIssuerJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims))
                .issuer("https://invalid.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(invalidIssuerJwt);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                googleTokenService.processToken(idToken, provider, request, response));

        assertEquals("invalid_issuer", exception.getErrorCode());
        verify(tokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, sessionManager, securityContextManager);
    }

    @Test
    void processTokenInvalidAudienceShouldThrowException() throws OAuth2AuthenticationException {
        Jwt invalidAudienceJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("invalid-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(invalidAudienceJwt);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                googleTokenService.processToken(idToken, provider, request, response));

        assertEquals("invalid_audience", exception.getErrorCode());
        verify(tokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, sessionManager, securityContextManager);
    }

    @Test
    void processTokenMissingEmailClaimShouldThrowException() throws OAuth2AuthenticationException {
        Map<String, Object> claimsWithoutEmail = new HashMap<>(claims);
        claimsWithoutEmail.remove("email");
        Jwt jwtWithoutEmail = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithoutEmail))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(jwtWithoutEmail);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                googleTokenService.processToken(idToken, provider, request, response));

        assertEquals("missing_email", exception.getErrorCode());
        verify(tokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, sessionManager, securityContextManager);
    }

    @Test
    void processTokenEmptyTokenShouldThrowException() throws OAuth2AuthenticationException {
        // Stub tokenDecoder.decode to throw a JwtException for an empty token
        when(tokenDecoder.decode("")).thenThrow(new InvalidRequestException("invalid_request","Empty token"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                googleTokenService.processToken("", provider, request, response));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        verifyNoInteractions(userMetadataService, sessionManager, securityContextManager);
        verify(tokenDecoder).decode("");
    }

    @Test
    void processTokenInvalidTokenFormatShouldThrowException() throws OAuth2AuthenticationException {
        when(tokenDecoder.decode(idToken)).thenThrow(new InvalidRequestException("invalid_token", "Invalid token format"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                googleTokenService.processToken(idToken, provider, request, response));

        assertEquals("invalid_token", exception.getErrorCode());
        verify(tokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, sessionManager, securityContextManager);
    }

    @Test
    void processTokenWithExistingUserMetadataAndNullNameShouldUseSavedName() throws Exception {
        // Test when userMetadata exists and name is null - should use saved display name
        UserMetadataDTO existingMetadata = new UserMetadataDTO("Saved Name", "http://example.com/saved-pic.jpg", "test@example.com", null);
        
        Map<String, Object> claimsWithoutName = new HashMap<>(claims);
        claimsWithoutName.remove("name");
        Jwt jwtWithoutName = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithoutName))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(jwtWithoutName);
        when(userMetadataService.getUserMetadata("google-subject-id", provider))
                .thenReturn(createUserMetadata("Saved Name", "http://example.com/saved-pic.jpg"));
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Saved Name", "http://example.com/picture.jpg", "test@example.com"))
                .thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Saved Name", "http://example.com/picture.jpg", "test@example.com");
        verify(sessionManager).setupSession(eq(request), eq(provider), userMetadataDTOArgumentCaptor.capture(), eq("test-user-id"));
        
        UserMetadataDTO capturedUserMetadata = userMetadataDTOArgumentCaptor.getValue();
        assertEquals("Saved Name", capturedUserMetadata.getDisplayName());
    }

    @Test
    void processTokenWithExistingUserMetadataAndBlankNameShouldUseSavedName() throws Exception {
        // Test when userMetadata exists and name is blank - should use saved display name
        Map<String, Object> claimsWithBlankName = new HashMap<>(claims);
        claimsWithBlankName.put("name", "   ");
        Jwt jwtWithBlankName = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithBlankName))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(jwtWithBlankName);
        when(userMetadataService.getUserMetadata("google-subject-id", provider))
                .thenReturn(createUserMetadata("Saved Display Name", "http://example.com/saved-pic.jpg"));
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Saved Display Name", "http://example.com/picture.jpg", "test@example.com"))
                .thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Saved Display Name", "http://example.com/picture.jpg", "test@example.com");
    }

    @Test
    void processTokenWithExistingUserMetadataAndNullPictureShouldUseSavedPicture() throws Exception {
        // Test when userMetadata exists and picture is null - should use saved picture URL
        Map<String, Object> claimsWithoutPicture = new HashMap<>(claims);
        claimsWithoutPicture.remove("picture");
        Jwt jwtWithoutPicture = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithoutPicture))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(jwtWithoutPicture);
        when(userMetadataService.getUserMetadata("google-subject-id", provider))
                .thenReturn(createUserMetadata("Test User", "http://example.com/saved-picture.jpg"));
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/saved-picture.jpg", "test@example.com"))
                .thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/saved-picture.jpg", "test@example.com");
        verify(sessionManager).setupSession(eq(request), eq(provider), userMetadataDTOArgumentCaptor.capture(), eq("test-user-id"));
        
        UserMetadataDTO capturedUserMetadata = userMetadataDTOArgumentCaptor.getValue();
        assertEquals("http://example.com/saved-picture.jpg", capturedUserMetadata.getProfilePictureUrl());
    }

    @Test
    void processTokenWithExistingUserMetadataAndBlankPictureShouldUseSavedPicture() throws Exception {
        // Test when userMetadata exists and picture is blank - should use saved picture URL
        Map<String, Object> claimsWithBlankPicture = new HashMap<>(claims);
        claimsWithBlankPicture.put("picture", "");
        Jwt jwtWithBlankPicture = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithBlankPicture))
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(tokenDecoder.decode(idToken)).thenReturn(jwtWithBlankPicture);
        when(userMetadataService.getUserMetadata("google-subject-id", provider))
                .thenReturn(createUserMetadata("Test User", "http://example.com/saved-pic.jpg"));
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/saved-pic.jpg", "test@example.com"))
                .thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/saved-pic.jpg", "test@example.com");
    }

    @Test
    void processTokenWithDecryptionExceptionShouldThrowRuntimeException() throws Exception {
        // Test the DecryptionException catch block
        when(tokenDecoder.decode(idToken)).thenReturn(validJwt);
        when(userMetadataService.getUserMetadata("google-subject-id", provider))
                .thenThrow(new io.mosip.mimoto.exception.DecryptionException("DEC_001", "Decryption failed"));

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                googleTokenService.processToken(idToken, provider, request, response));

        verify(tokenDecoder).decode(idToken);
        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verifyNoInteractions(sessionManager, securityContextManager);
    }

    @Test
    void processTokenWithNullUserMetadataShouldProceedNormally() throws Exception {
        // Test when userMetadata is null - should proceed with token claims
        when(tokenDecoder.decode(idToken)).thenReturn(validJwt);
        when(userMetadataService.getUserMetadata("google-subject-id", provider)).thenReturn(null);
        when(userMetadataService.updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/picture.jpg", "test@example.com"))
                .thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(userMetadataService).getUserMetadata("google-subject-id", provider);
        verify(userMetadataService).updateOrCreateUserMetadata("google-subject-id", provider, "Test User", "http://example.com/picture.jpg", "test@example.com");
        verify(sessionManager).setupSession(eq(request), eq(provider), any(UserMetadataDTO.class), eq("test-user-id"));
        verify(securityContextManager).setupSecurityContext(any(OAuth2AuthenticationToken.class), eq(request), eq(response));
    }

    // Helper method to create UserMetadata object for testing
    private UserMetadata createUserMetadata(String displayName, String pictureUrl) {
        UserMetadata metadata = new UserMetadata();
        metadata.setDisplayName(displayName);
        metadata.setProfilePictureUrl(pictureUrl);
        return metadata;
    }
}