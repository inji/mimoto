package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@Schema(description = "Generic response payload carrying user details returned by upstream services.")
public class Response {
    @Schema(description = "Identifier of the user.",
            example = "user-123")
    String userId;
    @Schema(description = "Mobile number of the user.",
            example = "+919876543210")
    String mobile;
    @Schema(description = "Email address of the user.",
            example = "john.doe@example.com")
    String mail;
    @Schema(description = "Language code associated with the user.",
            example = "eng")
    String langCode;
    @Schema(description = "Password or password placeholder returned by the upstream system.",
            example = "********")
    String userPassword;
    @Schema(description = "Display name of the user.",
            example = "John Doe")
    String name;
    @Schema(description = "Role assigned to the user.",
            example = "USER")
    String role;
}
