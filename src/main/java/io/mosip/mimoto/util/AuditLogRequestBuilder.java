package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.AuditLogConstant;
import io.mosip.mimoto.constant.LoggerFileConstant;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.AuditRequestDto;
import io.mosip.mimoto.dto.AuditResponseDto;
import io.mosip.mimoto.exception.ApisResourceAccessException;
import io.mosip.mimoto.service.RestClientService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * The Class AuditRequestBuilder.
 *
 * @author Rishabh Keshari
 */
@Slf4j
@Component
public class AuditLogRequestBuilder {

    /** The registration processor rest service. */
    @Autowired
    private RestClientService<Object> registrationProcessorRestService;

    @Autowired
    private Environment env;

    private static final String AUDIT_SERVICE_ID = "mosip.print.audit.id";
    private static final String REG_PROC_APPLICATION_VERSION = "mosip.print.application.version";
    private static final String DATETIME_PATTERN = "mosip.print.datetime.pattern";

    /**
     * Creates the audit request builder.
     *
     * @param description
     *                       the description
     * @param eventId
     *                       the event id
     * @param eventName
     *                       the event name
     * @param eventType
     *                       the event type
     * @param registrationId
     *                       the registration id
     * @return the audit response dto
     */
    @SuppressWarnings("unchecked")
    public ResponseWrapper<AuditResponseDto> createAuditRequestBuilder(String description, String eventId, String eventName, String eventType, String registrationId, ApiName apiname) {
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                registrationId,
                "AuditLogRequestBuilder:: createAuditRequestBuilder(String description, String eventId, String eventName, String eventType,\r\n            String registrationId, ApiName apiname)::entry");

        AuditRequestDto auditRequestDto = new AuditRequestDto();
        RequestWrapper<AuditRequestDto> requestWrapper = new RequestWrapper<>();
        ResponseWrapper<AuditResponseDto> responseWrapper = new ResponseWrapper<>();
        try {
            auditRequestDto.setDescription(description);
            auditRequestDto.setActionTimeStamp(DateUtils.getUTCCurrentDateTimeString());
            auditRequestDto.setApplicationId(AuditLogConstant.MOSIP_4.toString());
            auditRequestDto.setApplicationName(AuditLogConstant.REGISTRATION_PROCESSOR.toString());
            auditRequestDto.setCreatedBy(AuditLogConstant.SYSTEM.toString());
            auditRequestDto.setEventId(eventId);
            auditRequestDto.setEventName(eventName);
            auditRequestDto.setEventType(eventType);
            auditRequestDto.setHostIp(ServerUtil.getServerUtilInstance().getServerIp());
            auditRequestDto.setHostName(ServerUtil.getServerUtilInstance().getServerName());
            auditRequestDto.setId(registrationId);
            auditRequestDto.setIdType(AuditLogConstant.REGISTRATION_ID.toString());
            auditRequestDto.setModuleId(null);
            auditRequestDto.setModuleName(null);
            auditRequestDto.setSessionUserId(AuditLogConstant.SYSTEM.toString());
            auditRequestDto.setSessionUserName(null);
            requestWrapper.setId(env.getProperty(AUDIT_SERVICE_ID));
            requestWrapper.setMetadata(null);
            requestWrapper.setRequest(auditRequestDto);
            requestWrapper.setRequesttime(DateUtils.getRequestTimeString());
            requestWrapper.setVersion(env.getProperty(REG_PROC_APPLICATION_VERSION));
            responseWrapper = (ResponseWrapper<AuditResponseDto>) registrationProcessorRestService.postApi(apiname, "",
                    "", requestWrapper, ResponseWrapper.class);
        } catch (ApisResourceAccessException arae) {

            log.error(arae.getMessage());

        }
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                registrationId,
                "AuditLogRequestBuilder:: createAuditRequestBuilder(String description, String eventId, String eventName, String eventType,\r\n"
                        + "            String registrationId, ApiName apiname)::exit");

        return responseWrapper;
    }

    @SuppressWarnings("unchecked")
    public ResponseWrapper<AuditResponseDto> createAuditRequestBuilder(String description, String eventId,
            String eventName, String eventType, String moduleId, String moduleName, String registrationId) {
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                registrationId,
                "AuditLogRequestBuilder:: createAuditRequestBuilder(String description, String eventId, String eventName, String eventType,String moduleId,String moduleName,\r\n"
                        + "            String registrationId)::entry");

        AuditRequestDto auditRequestDto;
        RequestWrapper<AuditRequestDto> requestWrapper = new RequestWrapper<>();
        ResponseWrapper<AuditResponseDto> responseWrapper = new ResponseWrapper<>();

        try {

            auditRequestDto = new AuditRequestDto();
            auditRequestDto.setDescription(description);
            auditRequestDto.setActionTimeStamp(DateUtils.getUTCCurrentDateTimeString());
            auditRequestDto.setApplicationId(AuditLogConstant.MOSIP_4.toString());
            auditRequestDto.setApplicationName(AuditLogConstant.REGISTRATION_PROCESSOR.toString());
            auditRequestDto.setCreatedBy(AuditLogConstant.SYSTEM.toString());
            auditRequestDto.setEventId(eventId);
            auditRequestDto.setEventName(eventName);
            auditRequestDto.setEventType(eventType);
            auditRequestDto.setHostIp(ServerUtil.getServerUtilInstance().getServerIp());
            auditRequestDto.setHostName(ServerUtil.getServerUtilInstance().getServerName());
            auditRequestDto.setId(registrationId);
            auditRequestDto.setIdType(AuditLogConstant.REGISTRATION_ID.toString());
            auditRequestDto.setModuleId(moduleId);
            auditRequestDto.setModuleName(moduleName);
            auditRequestDto.setSessionUserId(AuditLogConstant.SYSTEM.toString());
            auditRequestDto.setSessionUserName(null);
            requestWrapper.setId(env.getProperty(AUDIT_SERVICE_ID));
            requestWrapper.setMetadata(null);
            requestWrapper.setRequest(auditRequestDto);
            requestWrapper.setRequesttime(DateUtils.getRequestTimeString());
            requestWrapper.setVersion(env.getProperty(REG_PROC_APPLICATION_VERSION));
            responseWrapper = (ResponseWrapper<AuditResponseDto>) registrationProcessorRestService
                    .postApi(ApiName.AUDIT, "", "", requestWrapper, ResponseWrapper.class);

        } catch (ApisResourceAccessException arae) {

            log.error(arae.getMessage());

        }
        log.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                registrationId,
                "AuditLogRequestBuilder:: createAuditRequestBuilder(String description, String eventId, String eventName, String eventType,String moduleId,String moduleName,\r\n"
                        + "            String registrationId)::exit");

        return responseWrapper;
    }

}
