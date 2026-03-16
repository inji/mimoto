package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.mimoto.AttestationStatement;
import io.mosip.mimoto.dto.mimoto.GenericResponseDTO;
import io.mosip.mimoto.util.AttestationOfflineVerify;
import io.mosip.mimoto.util.AttestationOnlineVerify;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/safetynet")
@Tag(name = SwaggerLiteralConstants.ATTESTATION_NAME, description = SwaggerLiteralConstants.ATTESTATION_DESCRIPTION)
public class AttestationServiceController {

    private final AttestationOfflineVerify attestationOfflineVerify;

    private final AttestationOnlineVerify attestationOnlineVerify;

    public AttestationServiceController(AttestationOfflineVerify attestationOfflineVerify, AttestationOnlineVerify attestationOnlineVerify) {
        this.attestationOfflineVerify = attestationOfflineVerify;
        this.attestationOnlineVerify = attestationOnlineVerify;
    }

    /**
     * Safetynet attestation verify using offline method.
     *
     * @param attestation
     * @return
     */
    @Operation(hidden = true)
    @PostMapping(path = "/offline/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> processOffline(@RequestBody String attestation)
    {
        try {
            AttestationStatement attestationStatement = attestationOfflineVerify.parseAndVerify(attestation);
            return new ResponseEntity<>(attestationStatement, HttpStatus.OK);
        } catch (Exception e) {
            GenericResponseDTO responseDTO = new GenericResponseDTO();
            responseDTO.setStatus("Error");
            responseDTO.setMessage(e.getMessage());

            return new ResponseEntity<>(responseDTO, HttpStatus.OK);
        }
    }

    /**
     * Safetynet attestation verify using online method with Google API.
     *
     * @param attestation
     * @return
     */
    @Operation(hidden = true)
    @PostMapping(path = "/online/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> processOnline(@RequestBody String attestation)
    {
        try {
            AttestationStatement attestationStatement = attestationOnlineVerify.parseAndVerify(attestation);
            return new ResponseEntity<>(attestationStatement, HttpStatus.OK);
        } catch (Exception e) {
            GenericResponseDTO responseDTO = new GenericResponseDTO();
            responseDTO.setStatus("Error");
            responseDTO.setMessage(e.getMessage());

            return new ResponseEntity<>(responseDTO, HttpStatus.OK);
        }
    }
}
