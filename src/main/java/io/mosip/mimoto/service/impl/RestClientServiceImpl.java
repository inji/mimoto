package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.LoggerFileConstant;
import io.mosip.mimoto.exception.ApisResourceAccessException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

/**
 * The Class RestClientServiceImpl.
 *
 * @author Rishabh Keshari
 */
@Slf4j
@Service
public class RestClientServiceImpl implements RestClientService<Object> {

    /** The rest api client. */
    @Autowired
    private RestApiClient restApiClient;

    /** The env. */
    @Autowired
    private Environment env;

    /*
     * (non-Javadoc)
     *
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#getApi(io.mosip.registration.
     * processor .core.code.ApiName,
     * io.mosip.registration.processor.core.code.RestUriConstant, java.lang.String,
     * java.lang.String, java.lang.Class)
     */
    @Override
    public Object getApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
            Class<?> responseType) throws ApisResourceAccessException {
        log.debug("RestClientServiceImpl::getApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());

        UriComponentsBuilder builder = null;
        UriComponents uriComponents = null;
        if (apiHostIpPort != null) {

            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
            if (!CollectionUtils.isEmpty(pathsegments)) {
                addPathSegments(pathsegments, builder);
            }

            if (!StringUtils.isEmpty(queryParamName)) {
                addQueryParam(queryParamName, queryParamValue, builder);
            }

            try {

                uriComponents = builder.build(false).encode();
                log.debug(uriComponents.toUri().toString(), "URI");
                obj = restApiClient.getApi(uriComponents.toUri(), responseType);

            } catch (Exception e) {
                log.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getCode(), e);

            }
        }
        log.debug("RestClientServiceImpl::getApi()::exit");
        return obj;
    }

    @Override
    public Object getApi(ApiName apiName, List<String> pathsegments, List<String> queryParamName,
            List<Object> queryParamValue,
            Class<?> responseType) throws ApisResourceAccessException {
        log.debug("RestClientServiceImpl::getApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());

        UriComponentsBuilder builder = null;
        UriComponents uriComponents = null;
        if (apiHostIpPort != null) {

            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
            if (!CollectionUtils.isEmpty(pathsegments)) {
                addPathSegments(pathsegments, builder);
            }

            if (!CollectionUtils.isEmpty(queryParamName)) {
                for (int i = 0; i < queryParamName.size(); i++) {
                    builder.queryParam(queryParamName.get(i), queryParamValue.get(i));
                }

            }

            try {

                uriComponents = builder.build(false).encode();
                log.debug(uriComponents.toUri().toString(), "URI");
                obj = restApiClient.getApi(uriComponents.toUri(), responseType);

            } catch (Exception e) {
                log.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getCode(), e);

            }
        }
        log.debug("RestClientServiceImpl::getApi()::exit");
        return obj;
    }

    public Object postApi(ApiName apiName, String queryParamName, String queryParamValue, Object requestedData,
            Class<?> responseType, MediaType mediaType) throws ApisResourceAccessException {
        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_ENTRY);

        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!StringUtils.isEmpty(queryParamName)) {
                addQueryParam(queryParamName, queryParamValue, builder);
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), mediaType, requestedData, responseType);

            } catch (Exception e) {
                log.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_EXIT);
        return obj;
    }

    /*
     * (non-Javadoc)
     *
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#postApi(io.mosip.registration.
     * processor.core.code.ApiName,
     * io.mosip.registration.processor.core.code.RestUriConstant, java.lang.String,
     * java.lang.String, java.lang.Object, java.lang.Class)
     */
    @Override
    public Object postApi(ApiName apiName, String queryParamName, String queryParamValue, Object requestedData,
            Class<?> responseType) throws ApisResourceAccessException {
        return postApi(apiName, queryParamName, queryParamValue, requestedData, responseType, null);
    }

    /*
     * (non-Javadoc)
     *
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#postApi(io.mosip.registration.
     * processor.core.code.ApiName, java.util.List, java.lang.String,
     * java.lang.String, java.lang.Object, java.lang.Class)
     */
    @Override
    public Object postApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
            Object requestedData, Class<?> responseType) throws ApisResourceAccessException {

        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_ENTRY);
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!CollectionUtils.isEmpty(pathsegments)) {
                for (String segment : pathsegments) {
                    if (!StringUtils.isEmpty(segment)) {
                        builder.pathSegment(segment);
                    }
                }

            }
            if (!StringUtils.isEmpty(queryParamName)) {
                addQueryParam(queryParamName, queryParamValue, builder);
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), null, requestedData, responseType);

            } catch (Exception e) {
                log.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_EXIT);
        return obj;
    }

    @Override
    public Object postApi(ApiName apiName, MediaType mediaType, List<String> pathsegments, List<String> queryParamName,
            List<Object> queryParamValue,
            Object requestedData, Class<?> responseType) throws ApisResourceAccessException {

        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_ENTRY);
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!CollectionUtils.isEmpty(pathsegments)) {
                addPathSegments(pathsegments, builder);
            }
            if (!CollectionUtils.isEmpty(queryParamName)) {

                for (int i = 0; i < queryParamName.size(); i++) {
                    builder.queryParam(queryParamName.get(i), queryParamValue.get(i));
                }
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), mediaType, requestedData, responseType);

            } catch (Exception e) {
                log.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_EXIT);
        return obj;
    }

    @Override
    public Object postApi(ApiName apiName,
                          Object requestedData, Class<?> responseType, boolean useBearerToken) throws ApisResourceAccessException {

        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_ENTRY);
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        if (apiHostIpPort != null) {
            try {
                obj = restApiClient.postApi(apiHostIpPort, MediaType.APPLICATION_JSON, requestedData, responseType, useBearerToken);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
                throw new ApisResourceAccessException(
                        PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);
            }
        }
        log.debug(LoggerFileConstant.REST_CLIENT_SERVICE_IMPL_POST_API_EXIT);
        return obj;
    }

    @Override
    public Object postApi(ApiName apiName,
                          Object requestedData,
                          Class<?> responseType,
                          boolean useBearerToken,
                          String issuerName) throws ApisResourceAccessException {

        log.debug("RestClientServiceImpl::postApi with issuer: {} routing",issuerName);

        String apiHostIpPort = env.getProperty(apiName.name());

        try {
            return restApiClient.postApi(
                    apiHostIpPort,
                    MediaType.APPLICATION_JSON,
                    requestedData,
                    responseType,
                    useBearerToken,
                    issuerName
            );
        } catch (Exception e) {
            throw new ApisResourceAccessException(
                    PlatformErrorMessages.MIMOTO_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);
        }
    }


    private static void addQueryParam(String queryParamName, String queryParamValue, UriComponentsBuilder builder) {
        String[] queryParamNameArr = queryParamName.split(",");
        String[] queryParamValueArr = queryParamValue.split(",");
        for (int i = 0; i < queryParamNameArr.length; i++) {
            builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
        }
    }

    private void addPathSegments(List<String> pathSegments, UriComponentsBuilder builder) {
        for (String segment : pathSegments) {
            if (!StringUtils.isEmpty(segment)) {
                builder.pathSegment(segment);
            }
        }
    }
}
