package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RequestValidator;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@Slf4j
@Tag(name = SwaggerLiteralConstants.IDP_NAME, description = SwaggerLiteralConstants.IDP_DESCRIPTION)
public class IdpController {
    private static final boolean USE_BEARER_TOKEN = true;
    private static final String DPOP_HEADER = "DPoP";

    private final RestClientService<Object> restClientService;

    private final JoseUtil joseUtil;

    private final IdpService idpService;

    private final RequestValidator requestValidator;

    public IdpController(RestClientService<Object> restClientService, JoseUtil joseUtil, IdpService idpService, RequestValidator requestValidator) {
        this.restClientService = restClientService;
        this.joseUtil = joseUtil;
        this.idpService = idpService;
        this.requestValidator = requestValidator;
    }

    @Operation(summary = SwaggerLiteralConstants.IDP_BINDING_OTP_SUMMARY, description = SwaggerLiteralConstants.IDP_BINDING_OTP_DESCRIPTION)
    @PostMapping(value = "/binding-otp", produces = MediaType.APPLICATION_JSON_VALUE)
    @SuppressWarnings("unchecked")
    public ResponseEntity<ResponseWrapper<BindingOtpResponseDto>> otpRequest(@Valid @RequestBody BindingOtpRequestDto requestDTO, BindingResult result) throws Exception {
        log.debug("Received binding-otp request");
        requestValidator.validateInputRequest(result);
        requestValidator.validateNotificationChannel(requestDTO.getRequest().getOtpChannels());
        ResponseWrapper<BindingOtpResponseDto> responseWrapper = new ResponseWrapper<>();
        try {
            ResponseWrapper<BindingOtpResponseDto> internalResponse = (ResponseWrapper<BindingOtpResponseDto>) restClientService.postApi(ApiName.BINDING_OTP, requestDTO, ResponseWrapper.class, USE_BEARER_TOKEN);
            if (internalResponse == null)
                throw new IdpException();
            return ResponseEntity.status(HttpStatus.OK).body(internalResponse);
        } catch (Exception e) {
            log.error("Wallet binding otp error occurred.", e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, PlatformErrorMessages.MIMOTO_OTP_BINDING_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }

    }

    @Operation(summary = SwaggerLiteralConstants.IDP_WALLET_BINDING_SUMMARY, description = SwaggerLiteralConstants.IDP_WALLET_BINDING_DESCRIPTION)
    @PostMapping(path = "/wallet-binding", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<WalletBindingResponseDto>> request(@RequestBody WalletBindingRequestDTO requestDTO)
            throws Exception {

        log.debug("Received wallet-binding request ");
        ResponseWrapper<WalletBindingResponseDto> responseWrapper = new ResponseWrapper<>();
        try {
            WalletBindingInnerRequestDto innerRequestDto = new WalletBindingInnerRequestDto();
            innerRequestDto.setChallengeList(requestDTO.getRequest().getChallengeList());
            innerRequestDto.setIndividualId(requestDTO.getRequest().getIndividualId());
            innerRequestDto.setPublicKey(JoseUtil.getJwkFromPublicKey(requestDTO.getRequest().getPublicKey()));
            innerRequestDto.setAuthFactorType(requestDTO.getRequest().getAuthFactorType());
            innerRequestDto.setFormat(requestDTO.getRequest().getFormat());

            WalletBindingInternalRequestDTO req = new WalletBindingInternalRequestDTO(requestDTO.getRequestTime(), innerRequestDto);

            ResponseWrapper<WalletBindingInternalResponseDto> internalResponse = (ResponseWrapper<WalletBindingInternalResponseDto>) restClientService
                    .postApi(ApiName.WALLET_BINDING,
                            req, ResponseWrapper.class, USE_BEARER_TOKEN);

            if (internalResponse == null)
                throw new IdpException();

            responseWrapper = joseUtil.addThumbprintAndKeyId(internalResponse);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception e) {
            log.error("Wallet binding error occurred ", e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, PlatformErrorMessages.MIMOTO_WALLET_BINDING_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }

    @Operation(summary = SwaggerLiteralConstants.IDP_GET_TOKEN_SUMMARY, description = SwaggerLiteralConstants.IDP_GET_TOKEN_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = {@Content(schema = @Schema(implementation = TokenResponseDTO.class), mediaType = "application/json")}),
            @ApiResponse(responseCode = "400", content = {@Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json")})})
    @PostMapping(value = {"/get-token/{issuer}"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getToken(@RequestParam Map<String, String> params, @PathVariable(required = true, name = "issuer") String issuer) {
        log.info("Reached the getToken Controller for Issuer " + issuer);
        ResponseWrapper<TokenResponseDTO> responseWrapper = new ResponseWrapper<>();
        try {
            params.put("issuer", issuer);
            TokenResponseDTO response = idpService.getTokenResponse(params);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception ex) {
            log.error("Exception Occurred while Invoking the Token Endpoint : ", ex);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(ex, PlatformErrorMessages.MIMOTO_FETCHING_TOKEN_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }

    @Operation(
            summary = SwaggerLiteralConstants.IDP_GET_TOKEN_V2_SUMMARY,
            description = SwaggerLiteralConstants.IDP_GET_TOKEN_V2_DESCRIPTION
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Token response from authorization server",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = TokenResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Authorization server error response returned as-is or invalid request detected by Mimoto",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(
                                    example = "{\"error\":\"invalid_request\",\"error_description\":\"Invalid token request\"}"
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authorization server unauthorized response returned as-is",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(
                                    example = "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed\"}"
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal Mimoto error before receiving authorization server response",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(
                                    example = "{\"error\":\"MIMOTO-XXX\",\"error_description\":\"Unable to fetch token\"}"
                            )
                    )
            )
    })
    @PostMapping(
            value = "/v2/get-token/{issuer}",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Object> getTokenV2(@RequestParam Map<String, String> params,
                                             @PathVariable(name = "issuer") String issuer,
                                             @RequestHeader(value = DPOP_HEADER, required = false) String dpopProof) {
        log.info("Reached the getTokenV2 Controller for Issuer {}", issuer);

        try {
            Map<String, String> tokenParams = new HashMap<>(params);
            tokenParams.put("issuer", issuer);

            ResponseEntity<String> response = idpService.getTokenResponseV2(tokenParams, dpopProof);

            // Hop-by-hop headers must not be forwarded (RFC 7230)
            Set<String> hopByHopHeaders = Set.of(
                    "transfer-encoding", "connection", "keep-alive",
                    "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"
            );
            HttpHeaders forwardHeaders = new HttpHeaders();
            response.getHeaders().forEach((name, values) -> {
                if (!hopByHopHeaders.contains(name.toLowerCase())) {
                    forwardHeaders.put(name, values);
                }
            });
            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(forwardHeaders)
                    .body(response.getBody());

        } catch (InvalidRequestException ex) {
            log.error("Invalid token request: ", ex);

            String[] errorObj = Utilities.handleExceptionWithErrorCode(
                    ex,
                    PlatformErrorMessages.MIMOTO_FETCHING_TOKEN_EXCEPTION.getCode()
            );

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "error", errorObj[0],
                            "error_description", errorObj[1]
                    ));

        } catch (Exception ex) {
            log.error("Exception occurred while invoking the token endpoint: ", ex);

            String[] errorObj = Utilities.handleExceptionWithErrorCode(
                    ex,
                    PlatformErrorMessages.MIMOTO_FETCHING_TOKEN_EXCEPTION.getCode()
            );

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "error", errorObj[0],
                            "error_description", errorObj[1]
                    ));
        }
    }
}
