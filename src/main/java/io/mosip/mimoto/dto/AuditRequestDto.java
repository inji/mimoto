package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The Audit Request class with {@link #actor}, {@link #action},
 * {@link #origin}, {@link #device}, {@link #description} fields to be captured
 * and recorded.
 *
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 */

/*
 * (non-Javadoc)
 * 
 * @see java.lang.Object#toString()
 */
@Data

/**
 * Instantiates a new audit request dto.
 */
@NoArgsConstructor

/**
 * Instantiates a new audit request dto.
 *
 * @param eventId         the event id
 * @param eventName       the event name
 * @param eventType       the event type
 * @param actionTimeStamp the action time stamp
 * @param hostName        the host name
 * @param hostIp          the host ip
 * @param applicationId   the application id
 * @param applicationName the application name
 * @param sessionUserId   the session user id
 * @param sessionUserName the session user name
 * @param id              the id
 * @param idType          the id type
 * @param createdBy       the created by
 * @param moduleName      the module name
 * @param moduleId        the module id
 * @param description     the description
 */
@AllArgsConstructor
@Schema(description = "Audit event payload recorded for security, workflow, and operational tracking.")
public class AuditRequestDto {

    /** The event id. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Unique event identifier for the audit action.")
    private String eventId;

    /** The event name. */
    @NotNull
    @Size(min = 1, max = 128)
    @Schema(description = "Human-readable event name associated with the audit record.")
    private String eventName;

    /** The event type. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Type or category of the audited event.")
    private String eventType;

    /** The action time stamp. */
    @NotNull
    @Schema(description = "Timestamp at which the audited action occurred, in ISO 8601 format.")
    private String actionTimeStamp;

    /** The host name. */
    @NotNull
    @Size(min = 1, max = 32)
    @Schema(description = "Host name of the system where the event was recorded.")
    private String hostName;

    /** The host ip. */
    @NotNull
    @Size(min = 1, max = 16)
    @Schema(description = "IP address of the host that recorded the event.")
    private String hostIp;

    /** The application id. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Identifier of the application that generated the audit event.")
    private String applicationId;

    /** The application name. */
    @NotNull
    @Size(min = 1, max = 128)
    @Schema(description = "Name of the application that generated the audit event.")
    private String applicationName;

    /** The session user id. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Identifier of the user associated with the audited session.")
    private String sessionUserId;

    /** The session user name. */
    @Size(min = 1, max = 128)
    @Schema(description = "Display name of the user associated with the audited session.")
    private String sessionUserName;

    /** The id. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Primary identifier involved in the audited action.")
    private String id;

    /** The id type. */
    @NotNull
    @Size(min = 1, max = 64)
    @Schema(description = "Type of the identifier involved in the audited action.")
    private String idType;

    /** The created by. */
    @NotNull
    @Size(min = 1, max = 255)
    @Schema(description = "Actor or system account that created the audit entry.")
    private String createdBy;

    /** The module name. */
    @Size(max = 128)
    @Schema(description = "Name of the module where the audited event originated.")
    private String moduleName;

    /** The module id. */
    @Size(max = 64)
    @Schema(description = "Identifier of the module where the audited event originated.")
    private String moduleId;

    /** The description. */
    @Size(max = 2048)
    @Schema(description = "Detailed description of the audited activity.")
    private String description;

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public void setEventName(String eventName) {
        this.eventName = eventName;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public void setActionTimeStamp(String actionTimeStamp) {
        this.actionTimeStamp = actionTimeStamp;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public void setHostIp(String hostIp) {
        this.hostIp = hostIp;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public void setSessionUserId(String sessionUserId) {
        this.sessionUserId = sessionUserId;
    }

    public void setSessionUserName(String sessionUserName) {
        this.sessionUserName = sessionUserName;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setIdType(String idType) {
        this.idType = idType;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public void setModuleId(String moduleId) {
        this.moduleId = moduleId;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}
