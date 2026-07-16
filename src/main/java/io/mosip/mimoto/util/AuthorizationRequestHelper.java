package io.mosip.mimoto.util;

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.dcql.query.DCQLQuery;

/**
 * Shared helpers for classifying OpenID4VP authorization requests using the
 * library's parsed {@code dcql_query}.
 */
public final class AuthorizationRequestHelper {

    private AuthorizationRequestHelper() {
    }

    /**
     * Returns {@code true} when the library parsed a DCQL request with a non-null
     * {@code dcql_query}.
     */
    public static boolean hasDcqlQuery(AuthorizationRequest authorizationRequest) {
        return authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest
                && dcqlRequest.getDcqlQuery() != null;
    }

    /**
     * Extracts the DCQL query from a parsed authorization request, if present.
     */
    public static DCQLQuery extractDcqlQuery(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest) {
            return dcqlRequest.getDcqlQuery();
        }
        return null;
    }
}
