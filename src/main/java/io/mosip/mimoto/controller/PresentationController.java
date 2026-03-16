package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@RestController
@Slf4j
@Tag(name = SwaggerLiteralConstants.PRESENTATION_NAME, description = SwaggerLiteralConstants.PRESENTATION_DESCRIPTION)
public class PresentationController {

    private final PresentationService presentationService;

    @Value("${mosip.inji.ovp.error.redirect.url.pattern}")
    String injiOvpErrorRedirectUrlPattern;

    @Value("${mosip.inji.web.redirect.url}")
    String injiWebRedirectUrl;

    private final VerifierService verifierService;

    private final ObjectMapper objectMapper;

    public PresentationController(PresentationService presentationService, VerifierService verifierService, ObjectMapper objectMapper) {
        this.presentationService = presentationService;
        this.verifierService = verifierService;
        this.objectMapper = objectMapper;
    }

    @Operation( summary = SwaggerLiteralConstants.PRESENTATION_AUTHORIZE_SUMMARY, description = SwaggerLiteralConstants.PRESENTATION_AUTHORIZE_DESCRIPTION)
    @ApiResponses({ @ApiResponse(responseCode = "302", content = { @Content(mediaType = "application/text") }) })
    @GetMapping("/authorize")
    public void performAuthorization(HttpServletResponse response,
                                     @RequestParam("response_type") @Schema(description = "Response Type of the Presentation" , defaultValue = "vp_token") String responseType,
                                     @RequestParam("resource") @Schema(description = "URL Encoded Resource url of the Credential ")  String resource,
                                     @RequestParam("presentation_definition")  @Schema(description = "URL Encoded presentation definition") String presentationDefinition,
                                     @RequestParam("client_id") @Schema(description = "URL Encoded Client Id") String clientId,
                                     @RequestParam(name = "redirect_uri", required = false) @Schema(description = "URL Encoded Redirect URI") String redirectUri,
                                     @RequestParam(name = "state", required = false) @Schema(description = "Unique session identifier to prevent CSRF") String state,
                                     @RequestParam(name = "nonce", required = false) @Schema(description = "Cryptographic challenge used to bind the presentation to this request") String nonce,
                                     @RequestParam(name = "response_uri", required = false) @Schema(description = "Where to send the VP token") String responseUri,
                                     @RequestParam(name = "response_mode", required = false) @Schema(description = "Specifies how the Verifier will receive the Authorization Response from the Wallet") String responseMode) throws IOException {

        try {
            log.info("Started Presentation Authorization in the controller.");
            verifierService.validateVerifier(clientId, redirectUri);
            PresentationDefinitionDTO presentationDefinitionDTO = objectMapper.readValue(presentationDefinition, PresentationDefinitionDTO.class);
            PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder()
                    .responseType(responseType)
                    .resource(resource)
                    .presentationDefinition(presentationDefinitionDTO)
                    .clientId(clientId)
                    .redirectUri(redirectUri)
                    .state(state)
                    .nonce(nonce)
                    .responseUri(responseUri)
                    .responseMode(responseMode)
                    .build();
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            log.info("Completed Presentation Authorization in the controller.");
            response.sendRedirect(redirectString);
        } catch( InvalidVerifierException exception){
            sendRedirect(response, injiWebRedirectUrl, exception.getErrorCode(), exception.getErrorText(), exception);
        } catch(VPNotCreatedException | InvalidCredentialResourceException exception){
            sendRedirect(response, redirectUri, exception.getErrorCode(), exception.getErrorText(), exception);
        } catch (Exception exception){
            sendRedirect(response, redirectUri, ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage(), exception);
        }
    }

    private void sendRedirect(HttpServletResponse response, String domain, String code, String message, Exception exception) throws IOException {
        log.error("Exception Occurred in Authorizing the presentation : \n\t code - " + code + "\n\t message - " + message + "\n\t Trace - " + Arrays.toString(exception.getStackTrace()));
        String injiVerifyRedirectString = String.format(injiOvpErrorRedirectUrlPattern,
                domain,
                code,
                URLEncoder.encode(message, StandardCharsets.UTF_8));
        response.setStatus(302);
        response.sendRedirect(injiVerifyRedirectString);
    }
}
