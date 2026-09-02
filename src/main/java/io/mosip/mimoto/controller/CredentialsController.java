package io.mosip.mimoto.controller;

import com.google.zxing.WriterException;
import io.mosip.mimoto.constant.DpopConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.DpopChallengeException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.DpopIssuanceSessionService;
import io.mosip.mimoto.service.IdpService;
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
import org.apache.commons.lang.StringUtils;
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

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

@RestController
@RequestMapping(value = "/credentials")
@Slf4j
@Tag(name = SwaggerLiteralConstants.CREDENTIALS_NAME, description = SwaggerLiteralConstants.CREDENTIALS_DESCRIPTION)
public class CredentialsController {

    private final CredentialService credentialService;

    private final IdpService idpService;

    private final DpopIssuanceSessionService dpopIssuanceSessionService;

    public CredentialsController(CredentialService credentialService, IdpService idpService,
                                 DpopIssuanceSessionService dpopIssuanceSessionService) {
        this.credentialService = credentialService;
        this.idpService = idpService;
        this.dpopIssuanceSessionService = dpopIssuanceSessionService;
    }

    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_DESCRIPTION,
            parameters = @Parameter(name = DpopConstants.OAUTH_STATE_HEADER, in = ParameterIn.HEADER, required = true,
                    description = "OAuth state that identifies the BFF DPoP issuance session created by POST /issuers/{issuer-id}/authorize",
                    schema = @Schema(type = "string")))
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = {@Content(mediaType = "application/pdf")}),
            @ApiResponse(responseCode = "400", content = {@Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json")})})
    @PostMapping("/download")
    public ResponseEntity<?> downloadCredentialAsPDF(
            @RequestHeader(value = DpopConstants.OAUTH_STATE_HEADER, required = false) String state,
            @RequestParam Map<String, String> params,
            HttpSession httpSession) {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        try {
            String issuerId = params.get("issuer");
            String credentialType = params.get("credential");
            String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
            String locale = params.get("locale");
            log.info("Initiated Token Call");
            TokenResponseDTO response = getTokenResponse(params, httpSession, state);
            String proof = dpopIssuanceSessionService.credentialProof(httpSession, state);

            log.info("Initiated Download Credential Call");
            ByteArrayInputStream inputStream;
            try {
                inputStream = credentialService.downloadCredentialAsPDF(issuerId, credentialType, response, credentialValidity, locale, proof);
            } catch (DpopChallengeException exception) {
                log.info("Retrying guest credential download after DPoP nonce challenge for issuer: {}", issuerId);
                proof = dpopIssuanceSessionService.retryCredentialProof(httpSession, state, exception);
                inputStream = credentialService.downloadCredentialAsPDF(issuerId, credentialType, response, credentialValidity, locale, proof);
            }
            dpopIssuanceSessionService.remove(httpSession, state);
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition")
                    .body(new InputStreamResource(inputStream));
        } catch (InvalidRequestException exception) {
            log.error("Invalid credential download request ", exception);
            return Utilities.handleErrorResponse(exception, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Exception occurred while fetching credential types ", exception);
            return Utilities.handleErrorResponse(exception, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (InvalidCredentialResourceException invalidCredentialResourceException) {
            log.error("Exception occurred while pushing the data to data share ", invalidCredentialResourceException);
            return Utilities.handleErrorResponse(invalidCredentialResourceException, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (VCVerificationException exception) {
            log.error("Exception occurred while verification of the verifiable Credential" + exception);
            return Utilities.handleErrorResponse(exception, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (ExternalServiceUnavailableException exception) {
            log.error("External service unavailable during credential download: ", exception);
            return Utilities.handleErrorResponse(exception, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Exception occurred while generating pdf ", exception);
            return Utilities.handleErrorResponse(exception, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    @ExceptionHandler({AuthorizationServerWellknownResponseException.class, InvalidWellknownResponseException.class})
    public ResponseEntity<Object> handleBadRequestException(Exception ex) {
        log.error("Credential download failed: ", ex);
        return Utilities.handleErrorResponse(ex, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
    }

    @ExceptionHandler({WriterException.class})
    public ResponseEntity<Object> handleServerErrorException(Exception ex) {
        log.error("Credential download server error: ", ex);
        return Utilities.handleErrorResponse(ex, PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
    }

    private TokenResponseDTO getTokenResponse(Map<String, String> params, HttpSession httpSession, String state)
            throws ApiNotAccessibleException, IOException,
            AuthorizationServerWellknownResponseException,
            InvalidWellknownResponseException,
            IssuerOnboardingException {
        if (StringUtils.isBlank(state)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Issuance state is required");
        }
        params.put("state", state);
        TokenResponseDTO boundToken = dpopIssuanceSessionService.tokenFromSession(httpSession, state);
        if (boundToken != null) {
            return boundToken;
        }
        if (dpopIssuanceSessionService.find(httpSession, state) != null) {
            params.putIfAbsent("grant_type", "authorization_code");
            log.info("Exchanging authorization code inside credential download for BFF DPoP session");
            TokenResponseDTO exchanged = idpService.exchangeAndBindToken(params, httpSession);
            if (exchanged != null) {
                return exchanged;
            }
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "DPoP issuance session not found or token is not bound");
    }
}
