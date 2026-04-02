package io.mosip.mimoto.config;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuersService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.validation.Validator;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
public class IssuersValidationConfig implements ApplicationRunner {
    @Autowired
    IssuersService issuersService;
    @Autowired
    private Validator validator;
    private final String VALIDATION_ERROR_MSG = "\n\nValidation failed in Mimoto-issuers-config.json:";
    @Override
    public void run(ApplicationArguments args) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        log.info("Validation for mimoto-issuers-config.json STARTED");

        List<String> allErrors = new ArrayList<>();
        AtomicReference<Set<String>> credentialIssuers = new AtomicReference<>(new HashSet<>());

        IssuersDTO issuerDTOList = null;
        try {
            issuerDTOList = issuersService.getAllIssuers();
        } catch (Exception e) {
            log.error(VALIDATION_ERROR_MSG, e);
            throw new RuntimeException(VALIDATION_ERROR_MSG, e);
        }

        if (issuerDTOList != null) {
            for (int index = 0; index < issuerDTOList.getIssuers().size(); index++) {
                IssuerDTO issuerDTO = issuerDTOList.getIssuers().get(index);
                if (!issuerDTO.getProtocol().equals("OTP")) {
                    Errors errors = new BeanPropertyBindingResult(issuerDTO, "issuerV2DTO");
                    validator.validate(issuerDTO, errors);
                    String issuerId = issuerDTO.getIssuer_id();
                    boolean issuerHasErrors = false;

                    StringBuilder issuerErrors = new StringBuilder();
                    issuerErrors.append(String.format("Errors for issuer at index: %d with issuerId - %s%n", index, issuerId));

                    if (errors.hasErrors()) {
                        issuerHasErrors = true;
                        errors.getFieldErrors().stream()
                                .sorted(Comparator.comparing(FieldError::getField))
                                .forEach(error -> issuerErrors.append(String.format("- %s %s%n", error.getField(), error.getDefaultMessage())));

                    }

                    Set<String> currentIssuers = credentialIssuers.get();

                    if (!currentIssuers.add(issuerId)) {
                        issuerHasErrors = true;
                        issuerErrors.append("- Duplicate value found for the issuerId. More than one issuer is having the same issuerId").append("\n");
                    }

                    if (issuerHasErrors) {
                        allErrors.add(issuerErrors.toString());
                    }

                    credentialIssuers.set(currentIssuers);
                }
            };
        }

        if (!allErrors.isEmpty()) {
            StringBuilder fieldErrorsBuilder = new StringBuilder();
            allErrors.forEach(fieldErrorsBuilder::append);
            String fieldErrorsString = VALIDATION_ERROR_MSG + "\n" + fieldErrorsBuilder;
            log.error(fieldErrorsString);
            throw new RuntimeException(fieldErrorsString);
        }

        log.info("Validation for mimoto-issuers-config.json COMPLETED");
    }
}