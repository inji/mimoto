package io.mosip.mimoto.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Structured descriptor of an event type, split into namespace and event name components.")
public class Type {
    
    @NotBlank(message = "Namespace is required and cannot be blank")
    @Schema(description = "Namespace of the event type.", 
            example = "credentialshare")
    private String namespace;
    
    @NotBlank(message = "Name is required and cannot be blank")
    @Schema(description = "Specific event name within the namespace that identifies the action or status being reported.", 
            example = "credential-issued")
    private String name;
}
