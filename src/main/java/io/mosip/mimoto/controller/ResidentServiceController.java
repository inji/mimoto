package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.*;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.DateUtils;
import io.mosip.mimoto.util.RequestValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@Tag(name = SwaggerLiteralConstants.RESIDENT_NAME, description = SwaggerLiteralConstants.RESIDENT_DESCRIPTION)
public class ResidentServiceController {

    private final RestClientService<Object> restClientService;

    private final RequestValidator requestValidator;

    private final Environment env;

    public ResidentServiceController(RestClientService<Object> restClientService, RequestValidator requestValidator, Environment env) {
        this.restClientService = restClientService;
        this.requestValidator = requestValidator;
        this.env = env;
    }

    /**
     * Request a new OTP for OTP required API.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/otp")
    @Operation(summary = SwaggerLiteralConstants.RESIDENT_REQUEST_OTP_SUMMARY, description = SwaggerLiteralConstants.RESIDENT_REQUEST_OTP_DESCRIPTION)
    @SuppressWarnings("unchecked")
    public ResponseEntity<ResponseWrapper<CredentialRequestResponseDTO>> otpRequest(@Valid @RequestBody AppOTPRequestDTO requestDTO, BindingResult result) throws Exception {
        requestValidator.validateInputRequest(result);
        requestValidator.validateNotificationChannel(requestDTO.getOtpChannel());
        OTPRequestDTO mosipOTPRequestPayload = new OTPRequestDTO();
        mosipOTPRequestPayload.setVersion("1.0");
        mosipOTPRequestPayload.setId("mosip.identity.otp.internal");
        mosipOTPRequestPayload.setIndividualId(requestDTO.getIndividualId());
        mosipOTPRequestPayload.setIndividualIdType(requestDTO.getIndividualIdType());
        mosipOTPRequestPayload.setOtpChannel(requestDTO.getOtpChannel());
        mosipOTPRequestPayload.setRequestTime(DateUtils.getRequestTimeString());
        mosipOTPRequestPayload.setTransactionID(requestDTO.getTransactionID());

        ResponseWrapper<CredentialRequestResponseDTO> responseWrapper = (ResponseWrapper<CredentialRequestResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_OTP, "", "", mosipOTPRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Generate a new VID number using an UIN number.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/vid")
    @Operation(hidden = true)
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> vidGenerate(@RequestBody AppVIDGenerateRequestDTO requestDTO) throws Exception {
        VIDGenerateRequestDTO vidRequestDTO = new VIDGenerateRequestDTO();
        RequestWrapper<VIDGenerateRequestDTO> mosipVIDRequestPayload = new RequestWrapper<>();

        vidRequestDTO.setIndividualId(requestDTO.getIndividualId());
        vidRequestDTO.setIndividualIdType(requestDTO.getIndividualIdType());
        vidRequestDTO.setVidType(requestDTO.getVidType());
        vidRequestDTO.setOtp(requestDTO.getOtp());
        vidRequestDTO.setTransactionID(requestDTO.getTransactionID());
        mosipVIDRequestPayload.setId("mosip.resident.vid");
        mosipVIDRequestPayload.setVersion("v1");
        mosipVIDRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipVIDRequestPayload.setRequest(vidRequestDTO);

        ResponseWrapper<VIDGeneratorResponseDTO> responseWrapper = (ResponseWrapper<VIDGeneratorResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_VID, "", "", mosipVIDRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Request auth lock
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/auth/lock")
    @Operation(hidden = true)
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> authLock(@RequestBody AuthLockRequestDTO requestDTO) throws Exception {
        RequestWrapper<AuthLockRequestDTO> mosipAuthLockRequestPayload = new RequestWrapper<>();
        mosipAuthLockRequestPayload.setId("mosip.resident.authlock");
        mosipAuthLockRequestPayload.setVersion("v1");
        mosipAuthLockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthLockRequestPayload.setRequest(requestDTO);

        ResponseWrapper<AuthLockUnlockResponseDTO> responseWrapper = (ResponseWrapper<AuthLockUnlockResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AUTH_LOCK, "", "", mosipAuthLockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Request auth unlock
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/auth/unlock")
    @Operation(hidden = true)
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> authUnlock(@RequestBody AuthUnlockRequestDTO requestDTO) throws Exception {
        RequestWrapper<AuthUnlockRequestDTO> mosipAuthUnlockRequestPayload = new RequestWrapper<>();
        mosipAuthUnlockRequestPayload.setId("mosip.resident.authunlock");
        mosipAuthUnlockRequestPayload.setVersion("v1");
        mosipAuthUnlockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthUnlockRequestPayload.setRequest(requestDTO);

        ResponseWrapper<AuthLockUnlockResponseDTO> responseWrapper = (ResponseWrapper<AuthLockUnlockResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AUTH_UNLOCK, "", "", mosipAuthUnlockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @PostMapping("/req/individualId/otp")
    @Operation(summary = SwaggerLiteralConstants.RESIDENT_REQUEST_INDIVIDUALID_OTP_SUMMARY, description = SwaggerLiteralConstants.RESIDENT_REQUEST_INDIVIDUALID_OTP_DESCRIPTION)
    @SuppressWarnings("unchecked")
    public ResponseEntity<OTPResponseDTO> individualIdOtpRequest(@RequestBody IndividualIdOtpRequestDTO requestDTO) throws Exception {
        IndividualIdOTPRequestDTO mosipOTPRequestPayload = new IndividualIdOTPRequestDTO();
        mosipOTPRequestPayload.setId("mosip.identity.otp.internal");
        mosipOTPRequestPayload.setVersion("1.0");
        mosipOTPRequestPayload.setRequestTime(DateUtils.getRequestTimeString());
        mosipOTPRequestPayload.setIndividualId(requestDTO.getAid());
        mosipOTPRequestPayload.setOtpChannel(requestDTO.getOtpChannel());
        mosipOTPRequestPayload.setTransactionId(requestDTO.getTransactionID());

        OTPResponseDTO responseWrapper = (OTPResponseDTO) restClientService
                .postApi(ApiName.RESIDENT_INDIVIDUALID_OTP, "", "", mosipOTPRequestPayload, OTPResponseDTO.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @PostMapping("/aid/get-individual-id")
    @Operation(summary = SwaggerLiteralConstants.RESIDENT_GET_INDIVIDUALID_SUMMARY, description = SwaggerLiteralConstants.RESIDENT_GET_INDIVIDUALID_DESCRIPTION)
    @SuppressWarnings("unchecked")
    public ResponseEntity<ResponseWrapper<AidStatusResponseDTO>> aidGetIndividualId(@RequestBody AidStatusRequestDTO requestDTO) throws Exception {
        InternalAidStatusDTO req = new InternalAidStatusDTO(requestDTO.getAid(), requestDTO.getOtp(), requestDTO.getTransactionID());
        RequestWrapper<InternalAidStatusDTO> mosipAuthLockRequestPayload = new RequestWrapper<>();
        mosipAuthLockRequestPayload.setId("mosip.resident.checkstatus");
        mosipAuthLockRequestPayload.setVersion("1.0");
        mosipAuthLockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthLockRequestPayload.setRequest(req);

        ResponseWrapper<AidStatusResponseDTO> responseWrapper = (ResponseWrapper<AidStatusResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AID_GET_INDIVIDUALID, "", "", mosipAuthLockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

}
