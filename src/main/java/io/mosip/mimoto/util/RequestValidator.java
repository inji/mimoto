package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadRequestDTO;
import io.mosip.mimoto.exception.InvalidInputException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@Component
@Slf4j
public class RequestValidator {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(RequestValidator.class);

    @Value("${mosip.notificationtype:EMAIL|PHONE}")
    private String notificationType;
    public void validateInputRequest(BindingResult result){
        if(result.hasErrors()){
            FieldError fieldError = result.getFieldError();
            if(fieldError != null) {
                String errorMessage = fieldError.getField() + " " + fieldError.getDefaultMessage();
                throw new InvalidInputException(errorMessage);
            }
        }
    }

    public void validateNotificationChannel(List<String> otpChannelList) {
        List<String> incorrectNotificationChannel;
        log.info("\n Notification Types from application-default.properties in mosip-config - > {}", notificationType);
        incorrectNotificationChannel = otpChannelList
                .stream()
                .filter(otpChannel -> !notificationType.contains(otpChannel))
                .collect(Collectors.toList());
        if (incorrectNotificationChannel.size() > 0) {
            log.error("Invalid Input is received in otpChannels {}", String.join(",", incorrectNotificationChannel));
            throw new InvalidInputException(PlatformErrorMessages.MIMOTO_PGS_INVALID_INPUT_PARAMETER.getMessage() + " - " + "otpChannels");
        }
    }

    public void validateCredentialDownloadRequest(CredentialDownloadRequestDTO requestDTO, JsonNode requestedCredentialJSON) throws IOException, NoSuchFieldException {
        String response = "response";
        if(requestedCredentialJSON.has(response) && requestedCredentialJSON.get(response).has("id")) {
            String requestedIndividualId = requestedCredentialJSON.get(response).get("id").asText();
            if (!requestDTO.getIndividualId().equals(requestedIndividualId)) {
                throw new InvalidInputException(PlatformErrorMessages.MIMOTO_PGS_INVALID_INPUT_PARAMETER.getMessage() + " - " + "individualId");
            }
        }
    }
}
