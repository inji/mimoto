package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConstraintsDTO {
    FieldDTO[] fields;

    @JsonProperty("limitDisclosure")
    private String limitDisclosure;

}
