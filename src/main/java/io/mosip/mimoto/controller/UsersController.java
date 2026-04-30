package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.model.UserMetadata;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.EncryptionService;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = "/users/me")
@Tag(name = SwaggerLiteralConstants.USERS_NAME, description = SwaggerLiteralConstants.USERS_DESCRIPTION)
public class UsersController {
    private final UserMetadataRepository userMetadataRepository;

    private final EncryptionService encryptionService;

    public UsersController(UserMetadataRepository userMetadataRepository, EncryptionService encryptionService) {
        this.userMetadataRepository = userMetadataRepository;
        this.encryptionService = encryptionService;
    }

    /**
     * Retrieves user profile information, first checking the cache and then the database if needed
     *
     * @param authentication The authentication object containing user information
     * @param session        The HTTP session
     * @return ResponseEntity containing user metadata
     */
    @Operation(
            summary = "Retrieve user metadata",
            description = "First attempts to retrieve user metadata from the session cache. If not available, fetches from the database. This API is secured using session-based authentication.",
            operationId = "getUserProfile",
            security = @SecurityRequirement(name = "SessionAuth")
    )
    @ApiResponse(
            responseCode = "200",
            description = "User profile retrieved successfully",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserMetadataDTO.class),
                    examples = {
                            @ExampleObject(name = "Success response from DB", value = SwaggerExampleConstants.FETCH_USER_PROFILE_FROM_DB_SUCCESS),
                            @ExampleObject(name = "Success response from cache", value = SwaggerExampleConstants.FETCH_USER_CACHE_PROFILE_SUCCESS)
                    }
            )
    )
    @ApiResponse(responseCode = "401", description = "User data not found", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User not found", value = "{\"errorCode\": \"unauthorized\", \"errorMessage\": \"User not found. Please check your credentials or login again\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}"),
            @ExampleObject(name = "Decryption Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"Failed to process user data\"}"),
    }))
    @ApiResponse(
            responseCode = "503",
            description = "Service unavailable",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ErrorDTO.class),
                    examples = @ExampleObject(
                            name = "Database connection failure",
                            value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}"
                    )
            )
    )
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserMetadataDTO> getUserProfileInfo(Authentication authentication, HttpSession session) throws Exception {
        UserMetadataDTO userMetadataDTO = (UserMetadataDTO) session.getAttribute(SessionKeys.USER_METADATA);

        if (userMetadataDTO == null) {
            log.info("User metadata not found in cache, fetching from database");
            String identityProvider = (String) session.getAttribute("clientRegistrationId");
            UserMetadata userMetadata;
            try {
                userMetadata = fetchUserMetadata(authentication.getName(), identityProvider);

                // In case of fetching user info from DB, walletId is null.
                // Here login is required as data is unavailable in session
                userMetadataDTO = new UserMetadataDTO(
                        encryptionService.decrypt(userMetadata.getDisplayName()),
                        encryptionService.decrypt(userMetadata.getProfilePictureUrl()),
                        encryptionService.decrypt(userMetadata.getEmail()),
                        null
                );
                session.setAttribute(SessionKeys.USER_METADATA, userMetadataDTO);
            } catch (UnauthorizedAccessException exception) {
                log.error("Error occurred while retrieving user profile: ", exception);
                return Utilities.getErrorResponseEntityWithoutWrapper(
                        exception,
                        ErrorConstants.INVALID_USER.getErrorCode(),
                        HttpStatus.UNAUTHORIZED,
                        MediaType.APPLICATION_JSON
                );
            } catch (DecryptionException e) {
                log.error("Error occurred while decrypting user data: ", e);
                return Utilities.getErrorResponseEntityWithoutWrapper(
                        new RuntimeException("Failed to process user data"),
                        ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(),
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        MediaType.APPLICATION_JSON
                );
            }
        } else {
            // If data is available in cache, take walletId also from cache
            Object walletIdObj = session.getAttribute(SessionKeys.WALLET_ID);
            if (walletIdObj instanceof String walletId) {
                userMetadataDTO.setWalletId(walletId);
            }
            log.info("Retrieved user metadata from cache");
        }

        return ResponseEntity.status(HttpStatus.OK).body(userMetadataDTO);
    }

    private UserMetadata fetchUserMetadata(String providerSubjectId, String identityProvider) throws UnauthorizedAccessException {
        return userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider).
                orElseThrow(() ->
                        new UnauthorizedAccessException(ErrorConstants.UNAUTHORIZED_ACCESS.getErrorCode(), "User not found. Please check your credentials or login again")
                );
    }
}
