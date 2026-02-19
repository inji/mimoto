package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import jakarta.validation.Valid;

import java.util.List;

@AllArgsConstructor
@Getter
public class IssuersResponseDTO {

    @Expose
    @Valid
    @Schema(description = "List of Onboarded Issuers")
    List<IssuerResponseDTO> issuers;

}