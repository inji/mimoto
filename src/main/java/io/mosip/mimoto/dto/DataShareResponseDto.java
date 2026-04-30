package io.mosip.mimoto.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response wrapper for data share creation APIs.")
public class DataShareResponseDto extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    @Schema(description = "Data share details returned on successful creation.")
    private DataShare dataShare;

    @Schema(description = "List of errors returned when data share creation fails.")
    private List<ErrorDTO> errors;

    public DataShare getDataShare() {
        return dataShare;
    }

    public List<ErrorDTO> getErrors() {
        return errors;
    }
}
