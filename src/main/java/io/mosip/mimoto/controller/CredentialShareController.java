package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.Gson;
import io.mosip.kernel.websub.api.annotation.PreAuthenticateContentAndVerifyIntent;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.AppCredentialRequestDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadRequestDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadResponseDTO;
import io.mosip.mimoto.dto.mimoto.GenericResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestStatusResponseDTO;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import io.mosip.mimoto.util.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/credentialshare")
@Slf4j
@Tag(name = SwaggerLiteralConstants.CREDENTIALS_SHARE_NAME, description = SwaggerLiteralConstants.CREDENTIALS_SHARE_DESCRIPTION)
public class CredentialShareController {

    private final CredentialShareServiceImpl credentialShareService;

    private final RestClientService<Object> restClientService;

    private final Environment env;

    @Value("${mosip.partner.encryption.key}")
    private String partnerEncryptionKey;

    @Value("${mosip.partner.id}")
    private String partnerId;

    private final RequestValidator requestValidator;

    private Gson gson = new Gson();

    private final Utilities utilities;

    public CredentialShareController(CredentialShareServiceImpl credentialShareService, RestClientService<Object> restClientService, Environment env, RequestValidator requestValidator, Utilities utilities) {
        this.credentialShareService = credentialShareService;
        this.restClientService = restClientService;
        this.env = env;
        this.requestValidator = requestValidator;
        this.utilities = utilities;
    }

    /**
     * Websub callback for Verifiable Credential share.
     *
     * @param eventModel
     * @return
     * @throws Exception
     */
    @PostMapping(path = {"/callback/notify", "/callback/notify/"},consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthenticateContentAndVerifyIntent(secret = "${mosip.event.secret}", callback = "/v1/mimoto/credentialshare/callback/notify", topic = "${mosip.event.topic}")
    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_SUMMARY, 
               description = SwaggerLiteralConstants.CREDENTIALS_SHARE_HANDLE_SUBSCRIBED_EVENT_DESCRIPTION)
    @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Credential share callback event payload delivered by the eventing system when the issuance workflow reaches a new state.",
                 required = true,
                 content = @Content(schema = @Schema(implementation = EventModel.class),
                                   mediaType = MediaType.APPLICATION_JSON_VALUE))
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", 
                     description = "Acknowledgment returned after Mimoto accepts a credential share callback event notification.",
                     content = @Content(schema = @Schema(implementation = GenericResponseDTO.class))),
        @ApiResponse(responseCode = "400", 
                     description = "Invalid request payload - Event model structure validation failed"),
        @ApiResponse(responseCode = "500", 
                     description = "Internal server error - Processing credential share event failed")
    })
    public ResponseEntity<GenericResponseDTO> handleSubscribeEvent(@jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody EventModel eventModel)
            throws Exception {
        log.info("Received websub event:: transaction id = " + eventModel.getEvent().getTransactionId());
        GenericResponseDTO responseDTO = new GenericResponseDTO();
        Path vcRequestIdPath = Path.of(
            utilities.getDataPath(),
            String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, eventModel.getEvent().getTransactionId())
        );
        // Only process event if request id file exists in the storage.
        if (vcRequestIdPath.toFile().exists()) {
            boolean documentGenerated = credentialShareService.generateDocuments(eventModel);
            log.info("Credential share process status: {} for event id: {}", documentGenerated, eventModel.getEvent().getId());
        } else {
            log.warn("Event transaction id could not found in the storage, skipping...");
        }
        responseDTO.setStatus("OK");
        responseDTO.setMessage("Successfully issued.");
        return new ResponseEntity<GenericResponseDTO>(responseDTO, HttpStatus.OK);
    }

    /**
     * Request to publish a VC: print, share or download.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/request", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_SHARE_REQUEST_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_SHARE_REQUEST_VC_DESCRIPTION)
    public ResponseEntity<CredentialRequestResponseDTO> request(@org.springframework.web.bind.annotation.RequestBody AppCredentialRequestDTO requestDTO)
            throws Exception {

        if (StringUtils.isEmpty(requestDTO.getIndividualId())) {
            log.error("Received empty individual id for transaction id - " + requestDTO.getTransactionID());
        }

        // Call mosip resident service to issue a new credential
        RequestWrapper<CredentialRequestDTO> mosipCredentialRequestPayload = new RequestWrapper<CredentialRequestDTO>();

        CredentialRequestDTO credentialReqDTO = new CredentialRequestDTO();
        credentialReqDTO.setEncryptionKey(partnerEncryptionKey);
        credentialReqDTO.setIssuer(partnerId);
        credentialReqDTO.setIndividualId(requestDTO.getIndividualId());
        credentialReqDTO.setOtp(requestDTO.getOtp());
        credentialReqDTO.setTransactionID(requestDTO.getTransactionID());
        credentialReqDTO.setCredentialType(requestDTO.getCredentialType());
        credentialReqDTO.setUser(requestDTO.getUser());

        mosipCredentialRequestPayload.setId("mosip.resident.vid");
        mosipCredentialRequestPayload.setVersion("v1");
        mosipCredentialRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipCredentialRequestPayload.setRequest(credentialReqDTO);

        CredentialRequestResponseDTO response = (CredentialRequestResponseDTO)restClientService
                .postApi(ApiName.RESIDENT_CREDENTIAL_REQUEST, "", "", mosipCredentialRequestPayload,
                CredentialRequestResponseDTO.class, MediaType.APPLICATION_JSON);

        // Create request id file for later event.
        if (response.getErrors() == null || response.getErrors().isEmpty()) {
            Path vcRequestIdPath = Path.of(
                utilities.getDataPath(),
                String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, response.getResponse().getRequestId())
            );
            Files.write(vcRequestIdPath, gson.toJson(response).getBytes());
        }

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * The VC request status.
     *
     * @param requestId
     * @return
     * @throws Exception
     */
    @GetMapping(path = "/request/status/{requestId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_SHARE_REQUEST_VC_STATUS_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_SHARE_REQUEST_VC_STATUS_DESCRIPTION)
    @SuppressWarnings("unchecked")
    public ResponseEntity<ResponseWrapper<CredentialRequestStatusResponseDTO>> requestStatus(@PathVariable("requestId") String requestId)
            throws Exception {

        List<String> pathSegment = new ArrayList<String>();
        pathSegment.add(requestId);
        ResponseWrapper<CredentialRequestStatusResponseDTO> responseWrapper = (ResponseWrapper<CredentialRequestStatusResponseDTO>) restClientService
                .getApi(ApiName.RESIDENT_CREDENTIAL_REQUEST_STATUS, pathSegment, "", "", ResponseWrapper.class);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Download a received and decrypted VC.
     * Original VC data and decrypted identity will be combined in a single response
     * to display on the frontend.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/download", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = SwaggerLiteralConstants.CREDENTIALS_SHARE_DOWNLOAD_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_SHARE_DOWNLOAD_VC_DESCRIPTION)
    public ResponseEntity<CredentialDownloadResponseDTO> download(@Valid @org.springframework.web.bind.annotation.RequestBody CredentialDownloadRequestDTO requestDTO, BindingResult result)
            throws Exception {
        try {
            requestValidator.validateInputRequest(result);
            JsonNode decryptedCredentialJSON = utilities.getDecryptedVC(requestDTO.getRequestId());
            JsonNode requestedCredentialJSON = utilities.getRequestVC(requestDTO.getRequestId());
            JsonNode credentialJSON = utilities.getVC(requestDTO.getRequestId());

            // Combine original encrypted verifiable credential and decrypted
            if (decryptedCredentialJSON != null && credentialJSON != null) {
                requestValidator.validateCredentialDownloadRequest(requestDTO, requestedCredentialJSON);
                CredentialDownloadResponseDTO credentialDownloadBody = new CredentialDownloadResponseDTO();
                credentialDownloadBody.setCredential(decryptedCredentialJSON);
                credentialDownloadBody.setVerifiableCredential(credentialJSON);

                // Remove cached data.
                utilities.removeCacheData(requestDTO.getRequestId());
                return ResponseEntity.ok().body(credentialDownloadBody);
            }

            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (IOException exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
