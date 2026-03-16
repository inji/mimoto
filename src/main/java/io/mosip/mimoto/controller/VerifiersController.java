package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Collections;


@RestController
@RequestMapping(value = "/verifiers")
@Slf4j
@Tag(name = SwaggerLiteralConstants.VERIFIERS_NAME, description = SwaggerLiteralConstants.VERIFIERS_DESCRIPTION)
public class VerifiersController {

    private final VerifierService verifierService;

    public VerifiersController(VerifierService verifierService) {
        this.verifierService = verifierService;
    }

    @Operation(summary = SwaggerLiteralConstants.VERIFIERS_GET_VERIFIERS_SUMMARY, description = SwaggerLiteralConstants.VERIFIERS_GET_VERIFIERS_DESCRIPTION)
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<VerifiersDTO>> getAllTrustedVerifiers() {
        ResponseWrapper<VerifiersDTO> responseWrapper = new ResponseWrapper<>();
        try {
            responseWrapper.setResponse(verifierService.getTrustedVerifiers());
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (ApiNotAccessibleException | IOException e) {
            log.error("Exception occurred while fetching trusted verifiers ", e);
            responseWrapper.setResponse(new VerifiersDTO(Collections.emptyList()));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }
}
