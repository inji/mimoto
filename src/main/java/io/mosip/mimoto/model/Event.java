package io.mosip.mimoto.model;

import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.Valid;

@Data
@Schema(description = "Event payload received through the credential share callback, containing event metadata and any data-share details needed for processing.")
public class Event {
    
    @NotBlank(message = "Event ID is required and cannot be blank")
    @Schema(description = "Unique identifier assigned to the event notification itself.", 
            example = "mosip.mimoto.operation")
    private String id;
    
    @NotBlank(message = "Transaction ID is required and cannot be blank")
    @Schema(description = "Transaction identifier linking this event back to the original credential issuance or sharing request.", 
            example = "2bc3bb7f-6156-46d1-ae03-bf7b76e0c257")
    private String transactionId;
    
    @NotNull(message = "Event type is required")
    @Valid
    @Schema(description = "Structured event type information describing the event namespace and event name.")
    private Type type;
    
    @NotBlank(message = "Timestamp is required and cannot be blank")
    @Schema(description = "Timestamp at which the event occurred in ISO 8601 format.", 
            example = "2026-04-08T12:00:00Z")
    private String timestamp;
    
    @Schema(description = "URI from which shared data or the resulting artifact can be retrieved.", 
            example = "https://api.example/data-share/123")
    private String dataShareUri;

    @Schema(description = "Additional event-specific attributes supplied by the publisher, such as credential share metadata or status details.")
    private Map<String, Object> data;

    public String getId() {
        return id;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public Type getType() {
        return type;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getDataShareUri() {
        return dataShareUri;
    }

    public Map<String, Object> getData() {
        return data;
    }
}
