package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;

@RestController
@Slf4j
@RequestMapping("/v2/issuers")
@Tag(name = SwaggerLiteralConstants.ISSUERS_V2_NAME, description = SwaggerLiteralConstants.ISSUERS_V2_DESCRIPTION)
public class IssuersV2Controller {

    private final IssuersService issuersService;

    public IssuersV2Controller(IssuersService issuersService) {
        this.issuersService = issuersService;
    }

    @Operation(summary = SwaggerLiteralConstants.ISSUERS_V2_GET_ISSUERS_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_V2_GET_ISSUERS_DESCRIPTION)
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<IssuersV2DTO>> getAllIssuers() {
        ResponseWrapper<IssuersV2DTO> responseWrapper = new ResponseWrapper<>();
        try {
            responseWrapper.setResponse(issuersService.getIssuersV2DTO());
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (ApiNotAccessibleException | IOException e) {
            log.error("Exception occurred while fetching issuers (V2)", e);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(responseWrapper);
        } catch (Exception e) {
            log.error("Exception occurred while fetching issuers (V2)", e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, API_NOT_ACCESSIBLE_EXCEPTION.getCode());
            responseWrapper.setErrors(Utilities.getErrors(errorObj[0], errorObj[1]));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }

    @Operation(summary = SwaggerLiteralConstants.ISSUERS_V2_GET_ISSUER_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_V2_GET_ISSUER_DESCRIPTION)
    @GetMapping(value = "/{issuer-id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<IssuerV2DTO>> getIssuerById(@PathVariable("issuer-id") String issuerId) {
        ResponseWrapper<IssuerV2DTO> responseWrapper = new ResponseWrapper<>();
        try {
            IssuerV2DTO issuer = issuersService.getIssuerV2Details(issuerId);
            responseWrapper.setResponse(issuer);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (InvalidIssuerIdException e) {
            log.error("Invalid issuer id {} passed (V2)", issuerId);
            responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_ISSUER_ID_EXCEPTION.getCode(), INVALID_ISSUER_ID_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseWrapper);
        } catch (ApiNotAccessibleException | IOException e) {
            log.error("Exception occurred while fetching issuer {} (V2)", issuerId, e);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(responseWrapper);
        } catch (Exception e) {
            log.error("Exception occurred while fetching issuer {} (V2)", issuerId, e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, API_NOT_ACCESSIBLE_EXCEPTION.getCode());
            responseWrapper.setErrors(Utilities.getErrors(errorObj[0], errorObj[1]));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }
}
