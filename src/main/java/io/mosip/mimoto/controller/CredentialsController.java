package io.mosip.mimoto.controller;

import com.google.zxing.WriterException;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.DpopChallengeException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.util.DpopResponseHelper;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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

    private final IdpService idpService;

    public CredentialsController(CredentialService credentialService, IdpService idpService) {
        this.credentialService = credentialService;
        this.idpService = idpService;
    }

    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")}),
            @ApiResponse(responseCode = "400", content = {@Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json")})})
    @PostMapping("/download")
    public ResponseEntity<?> downloadCredentialAsPDF(@RequestParam Map<String, String> params,
                                                     @RequestHeader(value = DpopConstants.DPOP_HEADER, required = false) String dpopProof)
            throws ApiNotAccessibleException, AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException, InvalidCredentialResourceException,
            VCVerificationException, ExternalServiceUnavailableException, WriterException, IOException {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        String issuerId = params.get("issuer");
        String credentialType = params.get("credential");
        String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
        String locale = params.get("locale");
        log.info("Initiated Token Call");
        TokenResponseDTO response = resolveTokenResponse(params, dpopProof);

        log.info("Initiated Download Credential Call");
        ByteArrayInputStream inputStream = credentialService.downloadCredentialAsPDF(
                issuerId, credentialType, response, credentialValidity, locale, dpopProof);
        return ResponseEntity
                .ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition, " + DpopResponseHelper.EXPOSED_DPOP_HEADERS)
                .body(new InputStreamResource(inputStream));
    }

    @ExceptionHandler(DpopChallengeException.class)
    public ResponseEntity<Object> handleDpopChallengeException(DpopChallengeException exception) {
        log.warn("Credential issuer returned DPoP nonce challenge");
        return DpopResponseHelper.challengeResponse(exception);
    }

    @ExceptionHandler({ApiNotAccessibleException.class, InvalidCredentialResourceException.class,
            VCVerificationException.class, AuthorizationServerWellknownResponseException.class,
            InvalidWellknownResponseException.class})
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

    private TokenResponseDTO resolveTokenResponse(Map<String, String> params, String dpopProof)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException {
        DpopResponseHelper.TokenResponseFromParams preIssuedToken =
                DpopResponseHelper.resolvePreIssuedToken(params, dpopProof);
        if (preIssuedToken != null) {
            log.info("Using client-provided access token for credential download");
            return preIssuedToken.tokenResponse();
        }
        log.info("Initiated Token Call");
        return idpService.getTokenResponse(params);
    }
}
