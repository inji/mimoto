package io.mosip.mimoto.controller;

import com.google.zxing.WriterException;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.DPoPSessionService;
import io.mosip.mimoto.service.PkceSessionManager;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping(value = "/credentials")
@Slf4j
@Tag(name = SwaggerLiteralConstants.CREDENTIALS_NAME, description = SwaggerLiteralConstants.CREDENTIALS_DESCRIPTION)
public class CredentialsController {

    private final CredentialService credentialService;

    private final DPoPSessionService dPoPSessionService;
    private final PkceSessionManager pkceSessionManager;

    public CredentialsController(CredentialService credentialService, DPoPSessionService dPoPSessionService,
                                 PkceSessionManager pkceSessionManager) {
        this.credentialService = credentialService;
        this.dPoPSessionService = dPoPSessionService;
        this.pkceSessionManager = pkceSessionManager;
    }

    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_DESCRIPTION,
            parameters = @Parameter(name = DPoPConstants.OAUTH_STATE_HEADER, in = ParameterIn.HEADER, required = true,
                    description = "OAuth state that identifies the DPoP session created by POST /issuers/{issuer-id}/authorize",
                    schema = @Schema(type = "string")),
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Request body parameters including issuer, credential type, storage expiry, locale, and authorization code."))
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")}),
            @ApiResponse(responseCode = "400", content = {@Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json")})})
    @PostMapping("/download")
    public ResponseEntity<InputStreamResource> downloadCredentialAsPDF(
            @RequestHeader(value = DPoPConstants.OAUTH_STATE_HEADER, required = false) String state,
            @RequestParam Map<String, String> params,
            HttpSession httpSession)
            throws ApiNotAccessibleException, AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException, InvalidCredentialResourceException,
            VCVerificationException, ExternalServiceUnavailableException, WriterException, IOException {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        String issuerId = params.get("issuer");
        String credentialType = params.get("credential");
        String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
        String locale = params.get("locale");
        try {
            log.info("Initiated Download Credential Call");
            ByteArrayInputStream inputStream = credentialService.downloadCredentialAsPDF(
                    issuerId, credentialType, credentialValidity, locale, params.get("code"), state, httpSession);
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition")
                    .body(new InputStreamResource(inputStream));
        } finally {
            dPoPSessionService.remove(httpSession, state);
            pkceSessionManager.remove(httpSession, state);
        }
    }

    @ExceptionHandler({
            InvalidRequestException.class,
            ApiNotAccessibleException.class,
            InvalidCredentialResourceException.class,
            VCVerificationException.class,
            AuthorizationServerWellknownResponseException.class,
            InvalidWellknownResponseException.class
    })
    public ResponseEntity<Object> handleBadRequestException(Exception ex) {
        log.error("Credential download failed: ", ex);
        return Utilities.handleErrorResponse(ex, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
    }

    @ExceptionHandler(ExternalServiceUnavailableException.class)
    public ResponseEntity<Object> handleExternalServiceUnavailableException(ExternalServiceUnavailableException ex) {
        log.error("External service unavailable during credential download: ", ex);
        return Utilities.handleErrorResponse(ex, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
    }

    @ExceptionHandler({WriterException.class, IOException.class})
    public ResponseEntity<Object> handleServerErrorException(Exception ex) {
        log.error("Credential download server error: ", ex);
        return Utilities.handleErrorResponse(ex, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
    }
}
