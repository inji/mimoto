package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class V1VCCredentialResponse {

    private List<Object> credentials;

    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public boolean hasError() {
        return error != null;
    }
}
