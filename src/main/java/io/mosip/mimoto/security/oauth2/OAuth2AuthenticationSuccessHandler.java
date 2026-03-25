package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final String authenticationSuccessRedirectUrl;

    public OAuth2AuthenticationSuccessHandler(@Value("${mosip.inji.web.authentication.success.redirect.url}") String authenticationSuccessRedirectUrl) {
        this.authenticationSuccessRedirectUrl = authenticationSuccessRedirectUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauth2Token.getPrincipal();

        HttpSession session = request.getSession(false);
        if (session == null) {
            log.error("Session not available");
            throw new ServletException("Session not available");
        }

        String clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        session.setAttribute("clientRegistrationId", clientRegistrationId);

        // Add user info to session for UI
        String displayName = oAuth2User.getAttribute("name");
        String profilePictureUrl = oAuth2User.getAttribute("picture");
        String email = oAuth2User.getAttribute("email");

        session.setAttribute(SessionKeys.USER_METADATA, new UserMetadataDTO(displayName, profilePictureUrl, email, null));

        String userId = oAuth2User.getAttribute("userId");
        session.setAttribute(SessionKeys.USER_ID, userId);

        response.sendRedirect(authenticationSuccessRedirectUrl);
    }
}