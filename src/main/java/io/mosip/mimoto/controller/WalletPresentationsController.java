package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.VPAuthorizationRequestDTO;
import io.mosip.mimoto.dto.VPResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.WalletPresentationService;
import io.mosip.mimoto.service.impl.SessionManager;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class WalletPresentationsController {

    @Autowired
    private WalletPresentationService walletPresentationService;

    @Autowired
    private SessionManager sessionManager;

    /**
     * Processes the Verifiable Presentation Authorization Request for a specific wallet.
     *
     * @param walletId               The unique identifier of the wallet.
     * @param httpSession            The HTTP session containing wallet details such as wallet ID.
     * @param vpAuthorizationRequest The Verifiable Presentation Authorization Request parameters.
     * @return The processed Verifiable Presentation details, including information about the verifier.
     */
    @Operation(summary = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUMMARY, description = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_DESCRIPTION, operationId = "processVPAuthorizationRequest", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string"))},
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Request body containing the Verifiable Presentation Authorization Request parameters.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = VPAuthorizationRequestDTO.class),
                            examples = @ExampleObject(
                                    name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_REQ_EXAMPLE_NAME,
                                    value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_REQ_EXAMPLE_VALUE
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Successfully processed the Verifiable Presentation Authorization Request.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VPResponseDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUCCESS_EXAMPLE_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_SUCCESS_EXAMPLE_VALUE)))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_MISSING_RESPONSE_TYPE_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_MISSING_RESPONSE_TYPE_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_INVALID_WALLET_ID_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_INVALID_WALLET_ID_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_WALLET_LOCKED_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_400_WALLET_LOCKED_VALUE)
    }))
    @ApiResponse(responseCode = "401", description = "Unauthorized user performing the Verifiable Presentation flow", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_401_USER_NOT_FOUND_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_401_USER_NOT_FOUND_VALUE)))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_VERIFIERS_FETCH_FAILED_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_VERIFIERS_FETCH_FAILED_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_SERVER_ERROR_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_SERVER_ERROR_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_INVALID_URI_SYNTAX_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_AUTHORIZATION_500_INVALID_URI_SYNTAX_VALUE)
    }))
    @PostMapping
    public ResponseEntity<VPResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody VPAuthorizationRequestDTO vpAuthorizationRequest) {
        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            VPResponseDTO verifiablePresentationResponseDTO = walletPresentationService.handleVPAuthorizationRequest(vpAuthorizationRequest.getAuthorizationRequestUrl(), walletId);

            VerifiablePresentationSessionData verifiablePresentationSessionData = new VerifiablePresentationSessionData(verifiablePresentationResponseDTO.getPresentationId(),
                    vpAuthorizationRequest.getAuthorizationRequestUrl(), Instant.now(),
                    verifiablePresentationResponseDTO.getVerifiablePresentationVerifierDTO().isPreregisteredWithWallet(), null);

            sessionManager.storePresentationSessionData(httpSession, verifiablePresentationSessionData, walletId);

            return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
        } catch (OpenID4VPExceptions exception) {
            log.error("Error occurred while processing the received VP Authorization Request from Verifier: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, exception.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException | VPNotCreatedException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (URISyntaxException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Gets matching credentials for a specific presentation request.
     *
     * @param walletId       The unique identifier of the wallet.
     * @param presentationId The unique identifier of the presentation.
     * @param httpSession    The HTTP session containing wallet details.
     * @return The matching credentials response with available credentials and
     * missing claims.
     */
    @Operation(summary = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUMMARY, description = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_DESCRIPTION, operationId = "getMatchingCredentials", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string")), @Parameter(name = "presentationId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Presentation.", schema = @Schema(type = "string"))})
    @ApiResponse(responseCode = "200", description = "Successfully retrieved matching credentials.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = MatchingCredentialsResponseDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUCCESS_EXAMPLE_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_SUCCESS_EXAMPLE_VALUE)))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_INVALID_WALLET_ID_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_INVALID_WALLET_ID_VALUE), @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_PRESENTATION_NOT_FOUND_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_400_PRESENTATION_NOT_FOUND_VALUE)}))
    @ApiResponse(responseCode = "401", description = "Unauthorized user performing the Verifiable Presentation flow", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_401_USER_NOT_FOUND_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_401_USER_NOT_FOUND_VALUE)))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_500_SERVER_ERROR_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_GET_MATCHING_CREDENTIALS_500_SERVER_ERROR_VALUE)))
    @GetMapping("/{presentationId}/credentials")
    public ResponseEntity<MatchingCredentialsResponseDTO> getMatchingCredentials(@PathVariable("walletId") String walletId, @PathVariable("presentationId") String presentationId, HttpSession httpSession) {

        WalletUtil.validateWalletId(httpSession, walletId);

        String base64Key = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
        if (base64Key == null) {
            log.warn("Wallet key not found in session for walletId: {}", walletId);
            return Utilities.getErrorResponseEntityFromPlatformErrorMessage(UNAUTHORIZED_ACCESS, HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
        }
        try {
            VerifiablePresentationSessionData sessionData = sessionManager.getPresentationSessionData(httpSession, walletId, presentationId);
            MatchingCredentialsDTO matchingCredentials = walletPresentationService.getMatchingCredentials(sessionData, walletId, base64Key);
            // Store the matching credentials and pre-filtered matched credentials in session cache before returning
            sessionManager.storeMatchingWalletCredentialsInPresentationSessionData(httpSession, walletId, sessionData, matchingCredentials.getMatchingCredentials());
            return ResponseEntity.status(HttpStatus.OK).body(matchingCredentials.getMatchingCredentialsResponse());
        } catch (ApiNotAccessibleException | IOException | VPNotCreatedException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (IllegalArgumentException exception) {
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }

    }

    /**
     * Handles presentation submission or verifier rejection based on the request content.
     * 
     * If the request contains selectedCredentials (and no error fields), it submits the presentation.
     * If the request contains errorCode and errorMessage (and no selected credentials), it rejects the verifier.
     *
     * @param walletId       The unique identifier of the wallet.
     * @param httpSession    The HTTP session containing wallet details.
     * @param presentationId The unique identifier of the presentation.
     * @param request        The request containing either selected credentials or error details.
     * @return Response indicating success/failure of the operation.
     */
    @Operation(
            summary = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_SUMMARY,
            description = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_DESCRIPTION,
            operationId = "handlePresentationAction",
            security = @SecurityRequirement(name = "SessionAuth"),
            parameters = {
                    @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the Wallet.", schema = @Schema(type = "string")),
                    @Parameter(name = "presentationId", in = ParameterIn.PATH, required = true, description = "The presentation session identifier.", schema = @Schema(type = "string"))
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Request body containing either selected credentials for submission or error details for rejection.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SubmitPresentationRequestDTO.class),
                            examples = {
                                    @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_SUBMIT_EXAMPLE_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_SUBMIT_EXAMPLE_VALUE),
                                    @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_REJECT_EXAMPLE_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_REQ_REJECT_EXAMPLE_VALUE)
                            }
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Successfully processed the request.", content = @Content(mediaType = "application/json", examples = {
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_200_SUBMITTED_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_200_SUBMITTED_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_200_REJECTED_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_200_REJECTED_VALUE)
    }))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_FORMAT_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_FORMAT_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_WALLET_ID_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_INVALID_WALLET_ID_VALUE),
            @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_PRESENTATION_NOT_FOUND_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_400_PRESENTATION_NOT_FOUND_VALUE)
    }))
    @ApiResponse(responseCode = "401", description = "Unauthorized user", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_401_UNAUTHORIZED_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_401_UNAUTHORIZED_VALUE)))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_500_SERVER_ERROR_NAME, value = SwaggerLiteralConstants.WALLET_PRESENTATIONS_HANDLE_ACTION_500_SERVER_ERROR_VALUE)))
    @PatchMapping("/{presentationId}")
    public ResponseEntity<?> handlePresentationAction(@PathVariable("walletId") String walletId, HttpSession httpSession, @PathVariable("presentationId") String presentationId, @Valid @RequestBody SubmitPresentationRequestDTO request) {

        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            VerifiablePresentationSessionData vpSessionData = sessionManager.getPresentationSessionData(httpSession, walletId, presentationId);

            if (vpSessionData == null) {
                log.error("No presentation session data found in session for presentationId: {}", presentationId);
                return Utilities.getErrorResponseEntityWithoutWrapper(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "presentationId not found in session"), INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
            }

            String base64Key = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
            if (base64Key == null) {
                log.warn("Wallet key not found in session for walletId: {}", walletId);
                return Utilities.getErrorResponseEntityFromPlatformErrorMessage(UNAUTHORIZED_ACCESS, HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
            }

            return walletPresentationService.handlePresentationAction(walletId, presentationId, request, vpSessionData, base64Key);

        }
        catch (IllegalArgumentException exception){
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }
}