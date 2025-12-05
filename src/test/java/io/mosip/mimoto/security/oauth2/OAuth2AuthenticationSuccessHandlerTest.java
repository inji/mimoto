package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationSuccessHandlerTest {

    @InjectMocks
    private OAuth2AuthenticationSuccessHandler successHandler;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private OAuth2AuthenticationToken oauth2Token;

    @Mock
    private OAuth2User oauth2User;

    private static final String AUTH_SUCCESS_REDIRECT_URL = "https://example.com/passcode";
    private static final String CLIENT_REGISTRATION_ID = "google";
    private static final String DISPLAY_NAME = "John Doe";
    private static final String PROFILE_PICTURE_URL = "https://example.com/profile.jpg";
    private static final String EMAIL = "john.doe@example.com";
    private static final String USER_ID = "user456";

    @Before
    public void setUp() throws Exception {
        ReflectionTestUtils.setField(successHandler, "authenticationSuccessRedirectUrl", AUTH_SUCCESS_REDIRECT_URL);

        when(request.getSession(false)).thenReturn(session);
    }

    @Test
    public void testOnAuthenticationSuccessSetsAttributesAndRedirects() throws Exception {
        when(oauth2Token.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttribute("name")).thenReturn(DISPLAY_NAME);
        when(oauth2User.getAttribute("picture")).thenReturn(PROFILE_PICTURE_URL);
        when(oauth2User.getAttribute("email")).thenReturn(EMAIL);
        when(oauth2User.getAttribute("userId")).thenReturn(USER_ID);

        successHandler.onAuthenticationSuccess(request, response, oauth2Token);

        verify(session).setAttribute("clientRegistrationId", CLIENT_REGISTRATION_ID);
        verify(session).setAttribute(SessionKeys.USER_ID, USER_ID);
        verify(response).sendRedirect(AUTH_SUCCESS_REDIRECT_URL);

        ArgumentCaptor<UserMetadataDTO> captor = ArgumentCaptor.forClass(UserMetadataDTO.class);
        verify(session).setAttribute(eq(SessionKeys.USER_METADATA), captor.capture());

        UserMetadataDTO dto = captor.getValue();
        assertEquals(DISPLAY_NAME, dto.getDisplayName());
        assertEquals(PROFILE_PICTURE_URL, dto.getProfilePictureUrl());
        assertEquals(EMAIL, dto.getEmail());
    }

    @Test
    public void testOnAuthenticationSuccessWithNullAttributes() throws Exception {
        when(oauth2Token.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttribute("name")).thenReturn(null);
        when(oauth2User.getAttribute("picture")).thenReturn(null);
        when(oauth2User.getAttribute("email")).thenReturn(null);
        when(oauth2User.getAttribute("userId")).thenReturn(USER_ID);

        successHandler.onAuthenticationSuccess(request, response, oauth2Token);

        verify(session).setAttribute("clientRegistrationId", CLIENT_REGISTRATION_ID);
        verify(session).setAttribute(SessionKeys.USER_ID, USER_ID);
        verify(response).sendRedirect(AUTH_SUCCESS_REDIRECT_URL);

        ArgumentCaptor<UserMetadataDTO> captor = ArgumentCaptor.forClass(UserMetadataDTO.class);
        verify(session).setAttribute(eq(SessionKeys.USER_METADATA), captor.capture());

        UserMetadataDTO dto = captor.getValue();
        assertNull(dto.getDisplayName());
        assertNull(dto.getProfilePictureUrl());
        assertNull(dto.getEmail());
    }

    @Test
    public void testOnAuthenticationSuccessWithNullSessionThrows() throws IOException {
        when(request.getSession(false)).thenReturn(null);

        ServletException thrown = assertThrows(ServletException.class, () ->
                successHandler.onAuthenticationSuccess(request, response, oauth2Token)
        );

        assertEquals("Session not available", thrown.getMessage());
        verify(response, never()).sendRedirect(anyString());
    }
}