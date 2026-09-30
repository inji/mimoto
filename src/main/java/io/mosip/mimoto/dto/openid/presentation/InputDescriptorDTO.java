package io.mosip.mimoto.dto.openid.presentation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class InputDescriptorDTO {
    String id;
    Map<String, Map<String, List<String>>> format;
    ConstraintsDTO constraints;

}
