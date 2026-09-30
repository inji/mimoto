package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

import jakarta.validation.Valid;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Response containing the list of issuers currently onboarded and exposed by Mimoto.")
public class IssuersDTO {

    @Expose
    @Valid
    @Schema(description = "List of onboarded issuers available for credential issuance flows.")
    List<IssuerDTO> issuers;

}
