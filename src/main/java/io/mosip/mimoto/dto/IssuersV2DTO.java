package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import jakarta.validation.Valid;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class IssuersV2DTO {

    @Valid
    @Schema(description = "List of Onboarded Issuers")
    List<IssuerV2DTO> issuers;

}
