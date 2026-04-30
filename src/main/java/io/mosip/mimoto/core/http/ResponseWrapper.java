package io.mosip.mimoto.core.http;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import io.mosip.mimoto.dto.ErrorDTO;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@Schema(description = "Generic API response wrapper containing the successful response payload or a list of errors.")
public class ResponseWrapper<T> {
    @NotNull
    @Valid
    @Schema(description = "Successful response payload returned by the API.")
    private T response;

    @Schema(description = "List of errors returned when the API could not process the request successfully.")
    private List<ErrorDTO> errors = new ArrayList<>();

    public T getResponse() {
        return response;
    }

    public void setResponse(T response) {
        this.response = response;
    }

    public List<ErrorDTO> getErrors() {
        return errors;
    }

    public void setErrors(List<ErrorDTO> errors) {
        this.errors = errors;
    }
}
