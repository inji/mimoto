package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.service.TrustedVerifierService;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
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
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import io.mosip.mimoto.dto.TrustedVerifierResponseDTO;

import static io.mosip.mimoto.exception.ErrorConstants.ERROR_ADDING_TRUSTED_VERIFIER;

@Slf4j
@RestController
@Validated
@RequestMapping("/wallets/{walletId}/trusted-verifiers")
public class WalletTrustedVerifiersController {

    @Autowired
    TrustedVerifierService trustedVerifierService;

    /**
     * Adds a trusted verifier for the specified wallet.
     *
     * Validates that the caller has an active session and that the provided
     * path `walletId` matches the wallet stored in the session. The request
     * body contains verifier details (for example: verifierId.
     * On success the created verifier record is returned with HTTP 201 Created.
     *
     * @param walletId               The unique identifier of the wallet. Must match the wallet id in session.
     * @param trustedVerifierRequest Trusted verifier details required to register the verifier for the wallet.
     * @param httpSession            HTTP session containing authenticated user and wallet information.
     * @return ResponseEntity containing the created TrustedVerifierResponseDTO and HTTP 201 status on success.
     */
    @Operation(
            summary = "Add a trusted verifier to a wallet",
            description = "Adds a trusted verifier for the specified wallet after validating the session and request. " +
                    "Requires an active session; the path walletId must match the wallet in session. Returns the created verifier details on success.",
            operationId = "addTrustedVerifier",
            security = @SecurityRequirement(name = "SessionAuth"),
            parameters = {
                    @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "The unique identifier of the wallet.", schema = @Schema(type = "string"))
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Trusted verifier details to add to the wallet.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TrustedVerifierRequest.class),
                            examples = @ExampleObject(
                                    name = "Trusted Verifier Request",
                                    value = "{ \"verifierId\": \"mock-client\" }"
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "201", description = "Trusted verifier created successfully.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = TrustedVerifierResponseDTO.class), examples = @ExampleObject(name = "Success response", value = "{ \"id\": \"2d598dfc-7218-cb7a7afd5a07\" }")))
    @ApiResponse(responseCode = "400", description = "Invalid request or missing required parameters.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Missing verifierId", value = "{\"errorCode\":\"invalid_request\",\"errorMessage\":\"Missing Input: verifierId is required\"}"),
            @ExampleObject(name = "Invalid Wallet ID", value = "{\"errorCode\":\"invalid_request\",\"errorMessage\":\"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
            @ExampleObject(name = "Duplicate verifier", value = "{\"errorCode\":\"duplicate_verifier\",\"errorMessage\":\"Verifier is already trusted for this wallet\"}")
    }))
    @ApiResponse(responseCode = "401", description = "Unauthorized - session invalid or missing user.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unauthorized", value = "{\"errorCode\":\"unauthorized\",\"errorMessage\":\"User ID not found in session\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\":\"internal_server_error\",\"errorMessage\":\"Failed to add trusted verifier\"}")))
    @PostMapping
    public ResponseEntity<TrustedVerifierResponseDTO> addTrustedVerifier(@PathVariable(name = "walletId") String walletId, @Valid @RequestBody TrustedVerifierRequest trustedVerifierRequest, HttpSession httpSession) {
        try {
            WalletUtil.validateWalletId(httpSession, walletId);

            TrustedVerifierResponseDTO trustedVerifierResponseDTO = trustedVerifierService.addTrustedVerifier(walletId, trustedVerifierRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body(trustedVerifierResponseDTO);
        } catch (DataAccessException e) {
            log.error("Unexpected error while adding trusted verifier for walletId: {} - Error: {}", walletId, e.getMessage(), e);
            return Utilities.getErrorResponseEntityWithoutWrapper(e,
                    ERROR_ADDING_TRUSTED_VERIFIER.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

}
