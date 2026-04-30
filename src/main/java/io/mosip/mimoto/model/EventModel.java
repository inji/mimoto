package io.mosip.mimoto.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.Valid;

@Data
@Schema(description = "Top-level callback payload delivered by the eventing system, including publisher metadata and the nested event details.")
public class EventModel {

    @NotBlank(message = "Publisher is required and cannot be blank")
    @Schema(description = "Publisher that emitted the event notification.", 
            example = "credentialshare")
    private String publisher;

    @NotBlank(message = "Topic is required and cannot be blank")
    @Schema(description = "Topic on which the event notification was published.", 
            example = "credential-issued")
    private String topic;

    @NotBlank(message = "Published timestamp is required and cannot be blank")
    @Schema(description = "Timestamp at which the event was published in ISO 8601 format.", 
            example = "2026-04-08T12:00:00Z")
    private String publishedOn;

    @NotNull(message = "Event object is required")
    @Valid
    @Schema(description = "Event payload delivered through the callback.")
    private Event event;

    public Event getEvent() {
        return event;
    }

    public void setEvent(Event event) {
        this.event = event;
    }
}
