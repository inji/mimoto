package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenService;
import io.mosip.mimoto.service.TokenServiceFactory;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = SwaggerLiteralConstants.ID_TOKEN_AUTHENTICATION_NAME, description = SwaggerLiteralConstants.ID_TOKEN_AUTHENTICATION_DESCRIPTION)
public class TokenAuthController {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String SESSION_CREATED = "Session created.";
    private static final String INVALID_TOKEN_MESSAGE = "Bearer ID token required.";


    private final TokenServiceFactory tokenServiceFactory;

    @Autowired
    public TokenAuthController(TokenServiceFactory tokenServiceFactory) {
        this.tokenServiceFactory = tokenServiceFactory;
    }

    @Operation(
            summary = "Login and create session using OAuth2 ID token",
            description = """
                    This API accepts an OAuth2 ID token in the Authorization header and establishes a session
                    by populating the Spring Security context.

                    Fetch the ID token from a supported OAuth2 provider (such as Google or Microsoft) and provide
                    it in the request as a Bearer token.
                    """,
            operationId = "loginWithOAuth2IdToken",
            security = @SecurityRequirement(name = "bearerAuth"),
            parameters = {
                    @Parameter(
                            name = "provider",
                            in = ParameterIn.PATH,
                            required = true,
                            description = "OAuth2 provider name. Example values: 'google', 'microsoft', 'facebook'.",
                            schema = @Schema(type = "string", example = "google")
                    ),
                    @Parameter(
                            name = "Authorization",
                            in = ParameterIn.HEADER,
                            required = true,
                            description = "OAuth2 ID token prefixed with 'Bearer '.",
                            schema = @Schema(type = "string", example = "Bearer eyJhbGciOi...")
                    )
            },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully logged in and session created.",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(type = "string"),
                                    examples = @ExampleObject(value = "Session created.")
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Bad Request - Missing/invalid header or unsupported provider.",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(implementation = io.mosip.mimoto.dto.ErrorDTO.class),
                                    examples = {

                                            @ExampleObject(name = "MissingToken", value = """
                                                    {
                                                      "errorCode": "INVALID_REQUEST",
                                                      "errorMessage": "Bearer ID token required."
                                                    }
                                                    """),
                                            @ExampleObject(name = "InvalidToken", value = """
                                                    {
                                                      "errorCode": "invalid_token",
                                                      "errorMessage": "An error occurred while attempting to decode the Jwt: Signed JWT rejected: Invalid signature"
                                                    }
                                                    """),
                                            @ExampleObject(name = "ExpiredToken", value = """
                                                    {
                                                      "errorCode": "invalid_token",
                                                      "errorMessage": "An error occurred while attempting to decode the Jwt: Jwt expired at 2025-06-10T12:00:00Z"
                                                    }
                                                    """
                                            )
                                    }
                            )
                    ),
            }
    )
    @PostMapping("/auth/{provider}/token-login")
    public ResponseEntity<Object> createSessionFromIdToken(@RequestHeader(value = "Authorization", required = false) String authorization, @PathVariable("provider") String provider, HttpServletRequest request, HttpServletResponse response) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new ErrorDTO(ErrorConstants.INVALID_REQUEST.getErrorCode(), INVALID_TOKEN_MESSAGE));
        }

        String idToken = authorization.substring(BEARER_PREFIX.length());
        try {
            TokenService tokenService = tokenServiceFactory.getTokenService(provider);
            tokenService.processToken(idToken, provider, request, response);
            return ResponseEntity.ok(SESSION_CREATED);
        } catch (OAuth2AuthenticationException e) {
            return Utilities.getErrorResponseEntityWithoutWrapper(e, e.getErrorCode(), HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
        }
    }
}