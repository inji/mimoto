package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
@Schema(description = "Authenticated user profile metadata returned to the frontend after login or session lookup.")
public class UserMetadataDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotBlank(message = "Display name is required and cannot be blank")
    @Schema(description = "Display name of the user provided by the Identity Provider",
            example = "John Doe")
    private String displayName;

    @NotBlank(message = "Profile picture URL is required and cannot be blank")
    @Schema(description = "Profile picture of the user provided by the Identity Provider",
            example = "https://example.com/profile.jpg")
    private String profilePictureUrl;

    @NotBlank(message = "Email is required and cannot be blank")
    @Schema(description = "Email of the user provided by the Identity Provider",
            example = "john.doe@example.com")
    private String email;

    @Schema(description = "Wallet id of the user in use",
            example = "123e4567-e89b-12d3-a456-426614174000")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String walletId;
}
