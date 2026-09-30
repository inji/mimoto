package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Schema(description = "Generic token request wrapper containing standard request metadata and the token request payload.")
public class TokenRequestDTO<T> {
    @Schema(description = "Request identifier.")
    public String id;
    @Schema(description = "Optional request metadata.")
    public Metadata metadata;
    @Schema(description = "Actual token request payload.")
    public T request;
    @Schema(description = "Timestamp at which the request was created, in ISO 8601 format.")
    public String requesttime;
    @Schema(description = "Version of the request contract.")
    public String version;
}
