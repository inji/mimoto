package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@ApiModel(description = "Model representing a Vid Request")
@Schema(description = "Request payload used to generate or manage a virtual ID.")
public class VidRequestDto {

    @Schema(description = "Type of virtual ID requested.",
            allowableValues = {"TEMPORARY", "PERPETUAL"})
    private String vidType;

    @JsonProperty("UIN")
    @Schema(description = "UIN for which the virtual ID operation is requested.")
    private String UIN;

    @Schema(description = "Desired or current status of the virtual ID.")
    private String vidStatus;

}
