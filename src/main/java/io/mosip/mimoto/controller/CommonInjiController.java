package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Tag(name = SwaggerLiteralConstants.COMMON_INJI_NAME, description = SwaggerLiteralConstants.COMMON_INJI_DESCRIPTION)
public class CommonInjiController {

    private final Map<String, String> injiConfig;

    public CommonInjiController(Map<String, String> injiConfig) {
        this.injiConfig = injiConfig;
    }

    @Operation( summary = SwaggerLiteralConstants.COMMON_INJI_GET_PROPERTIES_SUMMARY, description = SwaggerLiteralConstants.COMMON_INJI_GET_PROPERTIES_DESCRIPTION)
    @ApiResponses({@ApiResponse(responseCode = "200",content = { @Content(schema = @Schema(implementation = ResponseWrapper.class),
            examples = @ExampleObject( value = SwaggerExampleConstants.ALL_PROPERTIES_EXAMPLE),mediaType = "application/json") }  ) })
    @GetMapping(value = "/allProperties", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<Map<String, String>>> getAllProperties() {
        ResponseWrapper<Map<String, String>> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setResponse(injiConfig);
        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }
}
