package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static io.mosip.mimoto.util.WalletUtil.validateWalletId;

/**
 * REST controller for managing wallet credentials.
 */
@Slf4j
@RestController
@RequestMapping(value = "/wallets/{walletId}/credentials")
@Tag(name = SwaggerLiteralConstants.WALLET_CREDENTIALS_NAME, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DESCRIPTION)
public class WalletCredentialsController {

    private final WalletCredentialService walletCredentialService;
    private final IdpService idpService;

    @Autowired
    public WalletCredentialsController(WalletCredentialService walletCredentialService,
                                       IdpService idpService) {
        this.walletCredentialService = walletCredentialService;
        this.idpService = idpService;
    }

    /**
     * Downloads and stores a Verifiable Credential in the specified wallet.
     *
     * @param walletId                    The unique identifier of the wallet.
     * @param verifiableCredentialRequest Request body parameters including issuer, credential type, storage expiry, and locale.
     * @param httpSession                 The HTTP session containing wallet key and ID.
     * @return The stored Verifiable Credential details.
     * @throws InvalidRequestException If input parameters or session are invalid.
     */
    @Operation(summary = "Download and store a Verifiable Credential under a specific Wallet", description = "This API is secured using session-based authentication. Upon receiving a request, the session ID is extracted from the Cookie header and used to retrieve session details from Redis for authentication. It then retrieves the wallet key from the session and use it to decrypt the signing algorithm's secret key(which is used for signing the JWT in credential request) and encrypt the downloaded Verifiable Credential. If the process completes successfully, the credential is stored in the database and certain fields will be returned in the response. In case of any issues, an appropriate error response is returned.", operationId = "downloadCredential", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet", schema = @Schema(type = "string")),
            @Parameter(name = "Accept-Language", in = ParameterIn.HEADER, description = "The locale for the Verifiable Credential. It follows 2 letter language code", schema = @Schema(type = "string", defaultValue = "en"))},
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    description = "Request body parameters including issuer, credential type, storage expiry, and locale.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = VerifiableCredentialRequestDTO.class),
                            examples = @ExampleObject(
                                    name = "VerifiableCredentialRequest Example",
                                    value = "{ \"issuer\": \"issuerId\", \"credentialConfigurationId\": \"MockVerifiableCredential\", \"code\": \"authCode\", \"grantType\": \"authorization_code\", \"redirectUri\": \"https://example.com/cb\", \"codeVerifier\": \"verifier\" }"
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Verifiable Credential downloaded and stored successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiableCredentialResponseDTO.class)))
    @ApiResponse(responseCode = "400", description = "Bad request - Wallet key is null / blank or Wallet ID is null / blank / mismatch with session Wallet ID or required params are missing / invalid", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Invalid header Accept-Language", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Locale must be a 2-letter code\"}"),
            @ExampleObject(name = "Wallet ID is empty or blank", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Wallet ID cannot be blank\"}"),
            @ExampleObject(name = "Wallet ID not found in session", value = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}"),
            @ExampleObject(name = "Invalid Wallet ID", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
            @ExampleObject(name = "Wallet key not found in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Wallet key not found in session\"}"),
            @ExampleObject(name = "Invalid issuer", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"issuerId cannot be blank\"}"),
            @ExampleObject(name = "Invalid credentialConfigurationId", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"credentialConfigurationId cannot be blank\"}"),
            @ExampleObject(name = "Invalid code", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"code cannot be blank\"}"),
            @ExampleObject(name = "Invalid grantType", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"grantType cannot be blank\"}"),
            @ExampleObject(name = "Invalid redirectUri", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"redirectUri cannot be blank\"}"),
            @ExampleObject(name = "Invalid codeVerifier", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"codeVerifier cannot be blank\"}")})
    )
    @ApiResponse(responseCode = "500", description = "Internal server error - error occurred while serializing the VC response, encrypting the credential, or storing it", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "Credential already exists", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Duplicate credential for issuer and type\"}"), @ExampleObject(name = "Issuer config error", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Unable to fetch issuer configuration\"}"), @ExampleObject(name = "Failed to generate VC request", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Unable to generate credential request\"}"), @ExampleObject(name = "Signature verification failed", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}"), @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")}))
    @ApiResponse(responseCode = "503", description = "Service unavailable - error while fetching issuer or auth server well-known, downloading credential, or DB connection failure", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "API is not accessible", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Failed to download and store the credential\"}"), @ExampleObject(name = "Failed to download credential", value = "{\"errorCode\": \"server_unavailable\", \"errorMessage\": \"Unable to download credential from issuer\"}"), @ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")}))
    @PostMapping
    public ResponseEntity<VerifiableCredentialResponseDTO> downloadCredential(
            @RequestHeader(value = "Accept-Language", required = false, defaultValue = "en") @Pattern(regexp = "^[a-z]{2}$", message = "Locale must be a 2-letter code") String locale,
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @RequestBody @Valid VerifiableCredentialRequestDTO verifiableCredentialRequest,
            HttpSession httpSession) throws InvalidRequestException {
        if (!LocaleUtils.isValidLanguageCode(locale)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Locale must be a valid 2-letter code");
        }
        validateWalletId(httpSession, walletId);
        String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

        String issuerId = verifiableCredentialRequest.getIssuer();
        String credentialConfigurationId = verifiableCredentialRequest.getCredentialConfigurationId();

        log.info("Initiating token call for issuer: {}", issuerId);
        TokenResponseDTO tokenResponse;
        try {
            tokenResponse = idpService.getTokenResponse(verifiableCredentialRequest);
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException e) {
            log.error("Error fetching token response for issuer: {}", issuerId, e);
            return Utilities.getErrorResponseEntityFromPlatformErrorMessage(
                    CREDENTIAL_DOWNLOAD_EXCEPTION, HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
        }

        log.info("Fetching and storing Verifiable Credential for walletId: {}", walletId);

        try {
            VerifiableCredentialResponseDTO credentialResponseDTO = walletCredentialService.downloadVCAndStoreInDB(
                    issuerId, credentialConfigurationId, tokenResponse, locale, walletId, base64EncodedWalletKey);
            return ResponseEntity.status(HttpStatus.OK).body(credentialResponseDTO);
        } catch (ExternalServiceUnavailableException e) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
        } catch (CredentialProcessingException e) {
            log.error("Error processing credential download for walletId: {}", walletId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    /**
     * Fetches all credentials for a given wallet.
     *
     * @param walletId    The unique identifier of the wallet.
     * @param locale      The locale for credential retrieval.
     * @param httpSession The HTTP session containing wallet key and ID.
     * @return List of Verifiable Credential details.
     * @throws InvalidRequestException If session or wallet ID is invalid.
     */
    @Operation(summary = "Fetch all credentials for the given wallet", description = "This API is secured using session-based authentication. When a request is made, the session ID is extracted from the Cookie header and used to fetch session details from Redis for authentication. It then retrieves the wallet key from the session and uses it to decrypt all stored Verifiable Credentials for the given wallet. If successful, it returns a list of credentials otherwise an appropriate error is returned.", operationId = "fetchAllCredentialsForWallet", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the user's wallet from where the credential will be fetched", schema = @Schema(type = "string")),
            @Parameter(name = "Accept-Language", in = ParameterIn.HEADER, description = "Locale is used to determine the language in which credentials should be rendered. It follows 2 letter language code", schema = @Schema(type = "string"))})
    @ApiResponse(responseCode = "200", description = "Credentials retrieved successfully", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = VerifiableCredentialResponseDTO.class)), examples = @ExampleObject(value = SwaggerExampleConstants.FETCH_ALL_CREDENTIALS_OF_WALLET_SUCCESS)))
    @ApiResponse(responseCode = "400", description = "Bad request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Invalid Wallet Id", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
            @ExampleObject(name = "Wallet ID not found in session", value = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}"),
            @ExampleObject(name = "Wallet key not found in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Wallet key not found in session\"}"),
            @ExampleObject(name = "Invalid Accept-Language header", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Locale must be a 2-letter code\"}"),
    }))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")))
    @ApiResponse(responseCode = "503", description = "Service unavailable", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")))
    @GetMapping
    public ResponseEntity<List<VerifiableCredentialResponseDTO>> fetchAllCredentialsForGivenWallet(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @RequestHeader(value = "Accept-Language", defaultValue = "en") @Pattern(regexp = "^[a-z]{2}$", message = "Locale must be a 2-letter code") String locale,
            HttpSession httpSession) throws InvalidRequestException {
        if (!LocaleUtils.isValidLanguageCode(locale)) {
            log.info("Invalid Accept-Language header. Input was: {} ", locale);
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Locale must be a valid 2-letter code");
        }

        validateWalletId(httpSession, walletId);
        String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

        log.info("Fetching all credentials for walletId: {}", walletId);

        List<VerifiableCredentialResponseDTO> credentials = walletCredentialService.fetchAllCredentialsForWallet(
                walletId, base64EncodedWalletKey, locale);
        return ResponseEntity.status(HttpStatus.OK).body(credentials);

    }

    /**
     * Fetches a specific Verifiable Credential as a PDF.
     *
     * @param walletId     The unique identifier of the wallet.
     * @param credentialId The unique identifier of the credential.
     * @param locale       The locale for credential retrieval.
     * @param action       The action (inline or download) for PDF display.
     * @param httpSession  The HTTP session containing wallet key and ID.
     * @return The Verifiable Credential as a PDF stream.
     * @throws InvalidRequestException If session or parameters are invalid.
     */
    @Operation(summary = "Fetch a specific Verifiable Credential", description = "This API is protected using session-based authentication. When a request is received, the session ID is extracted from the Cookie header and used to fetch session data from Redis for user authentication. Upon successful authentication, the wallet key is retrieved from the session and used to decrypt the credential data obtained from the database.\n\nThe API retrieves a specific Verifiable Credential based on the provided wallet ID and credential ID. Depending on the action query parameter (inline or download) received in the request, the Content-Disposition header in the response is adjusted to either display the credential in the browser or prompt a file download. On success, the API returns the credential as a PDF byte stream. In case of any errors, an appropriate error response is returned.", operationId = "fetchVerifiableCredentialById", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the user's wallet", schema = @Schema(type = "string")),
            @Parameter(name = "credentialId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the Verifiable Credential to be retrieved", schema = @Schema(type = "string")),
            @Parameter(name = "Accept-Language", in = ParameterIn.QUERY, required = true, description = "Language preference in which the user expects the Verifiable Credential to be rendered", schema = @Schema(type = "string")),
            @Parameter(name = "action", in = ParameterIn.QUERY, description = "Controls how the credential should be displayed. If sent as download, the response will include a header to download the file. Defaults to inline.", schema = @Schema(type = "string", defaultValue = "inline"))})
    @ApiResponse(responseCode = "200", description = "Verifiable Credential fetched successfully", headers = @Header(name = HttpHeaders.CONTENT_DISPOSITION, description = "Indicates if the verifiable credential is displayed inline or downloaded", schema = @Schema(type = "string", example = "inline; filename=\"credential.pdf\"")), content = @Content(mediaType = "application/pdf", schema = @Schema(type = "string", format = "binary"), examples = @ExampleObject(value = "PDF content in Binary Format")))
    @ApiResponse(responseCode = "400", description = "Bad request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
            @ExampleObject(name = "Invalid Wallet Id", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
            @ExampleObject(name = "Wallet key not found in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Wallet key not found in session\"}"),
            @ExampleObject(name = "Wallet ID not found in session", value = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}"),
            @ExampleObject(name = "Invalid Accept header", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Accept header must be application/pdf\"}"),
    }))
    @ApiResponse(responseCode = "404", description = "Not Found - Credential not found for given Wallet ID and Credential ID", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "No credentials found", value = "{\"errorCode\": \"resource_not_found\", \"errorMessage\": \"The requested resource doesn’t exist.\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "Failed to decrypt the Credential", value = "{\"errorCode\": \"credential_fetch_error\", \"errorMessage\": \"Decryption failed\"}"), @ExampleObject(name = "Credential Type is invalid", value = "{\"errorCode\": \"credential_fetch_error\", \"errorMessage\": \"Invalid credential type configuration\"}"), @ExampleObject(name = "Exception occurred while fetching Issuer config", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Unable to fetch issuer configuration\"}"), @ExampleObject(name = "Exception occurred when generating PDF", value = "{\"errorCode\": \"credential_download_error\", \"errorMessage\": \"Failed to generate credential PDF\"}"), @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")}))
    @ApiResponse(responseCode = "503", description = "Service unavailable", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")))
    @GetMapping("/{credentialId}")
    public ResponseEntity<InputStreamResource> getVerifiableCredential(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @PathVariable("credentialId") @NotBlank(message = "Credential ID cannot be blank") String credentialId,
            @RequestHeader(value = "Accept") String accept,
            @RequestHeader(value = "Accept-Language", defaultValue = "en") @Pattern(regexp = "^[a-z]{2}$", message = "Locale must be a 2-letter code") String locale,
            @RequestParam(value = "action", defaultValue = "inline") @Pattern(regexp = "^(inline|download)$", message = "Action must be 'inline' or 'download'") String action,
            HttpSession httpSession) throws InvalidRequestException {

        try {
            if (!Objects.equals(accept, MediaType.APPLICATION_PDF_VALUE)) {
                log.error("Invalid Accept header: {}. Valid Accept headers are - [\"application/pdf\"]", accept);
                throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Accept header must be application/pdf");
            }
            validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

            log.info("Fetching credentialId: {} from walletId: {}", credentialId, walletId);

            WalletCredentialResponseDTO walletCredentialResponseDTO = walletCredentialService.fetchVerifiableCredential(
                    walletId, credentialId, base64EncodedWalletKey, locale);

            String dispositionType = "download".equalsIgnoreCase(action) ? "attachment" : "inline";
            String contentDisposition = String.format("%s; filename=\"%s\"", dispositionType, walletCredentialResponseDTO.getFileName());

            return ResponseEntity.ok()
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION)
                    .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(walletCredentialResponseDTO.getFileContentStream());
        } catch (CredentialNotFoundException e) {
            log.error("Credential not found for walletId: {} and credentialId: {}", walletId, credentialId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.NOT_FOUND, MediaType.APPLICATION_JSON);
        } catch (CredentialProcessingException e) {
            log.error("Error processing credential for walletId: {} and credentialId: {}", walletId, credentialId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        } catch (InvalidRequestException exception) {
            log.error("Error processing credential for walletId: {} and credentialId: {}", walletId, credentialId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception, exception.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (Exception exception){
            log.error("Unexpected error processing credential for walletId: {} and credentialId: {}", walletId, credentialId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    new CredentialProcessingException(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), "We are unable to process request now"),
                    ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(),
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    MediaType.APPLICATION_JSON);
        }

    }

    /**
     * Deletes a credential by its ID
     *
     * @param walletId     The ID of the wallet that owns the credential
     * @param credentialId The ID of the credential to delete
     * @return ResponseEntity with HTTP status 200 if successful, 404 if credential not found, or 500 for other errors
     */
    @Operation(summary = SwaggerLiteralConstants.WALLET_CREDENTIALS_DELETE_SUMMARY, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DELETE_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Credential successfully deleted"),
            @ApiResponse(responseCode = "400", description = "Bad request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {
                    @ExampleObject(name = "Invalid Wallet Id", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Invalid Wallet ID. Session and request Wallet ID do not match\"}"),
                    @ExampleObject(name = "Wallet ID not found in session", value = "{\"errorCode\": \"wallet_locked\", \"errorMessage\": \"Wallet is locked\"}"),
            })),
            @ApiResponse(responseCode = "404", description = "Credential not found"),
            @ApiResponse(responseCode = "500", description = "Internal server error", content = {@Content(mediaType = "application/json")})})
    @DeleteMapping("/{credentialId}")
    public ResponseEntity<?> deleteCredential(@PathVariable("walletId") String walletId,
                                              @PathVariable("credentialId") String credentialId,
                                              HttpSession httpSession) {
        try {
            log.info("Deleting credential with ID: {} for walletId: {}", credentialId, walletId);

            validateWalletId(httpSession, walletId);

            // Delete the credential
            walletCredentialService.deleteCredential(credentialId, walletId);
            return ResponseEntity.status(HttpStatus.OK).build();
        } catch (InvalidRequestException exception) {
            log.error("Invalid request: {}", exception.getMessage());
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    exception.getErrorCode(),
                    HttpStatus.BAD_REQUEST,
                    MediaType.APPLICATION_JSON);
        } catch (CredentialNotFoundException exception) {
            log.error("Credential not found: {}", exception.getMessage());
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    exception.getErrorCode(),
                    HttpStatus.NOT_FOUND,
                    MediaType.APPLICATION_JSON);
        }
    }
}
