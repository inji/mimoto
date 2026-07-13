package io.mosip.mimoto.util;

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.constants.SpecVersion;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthorizationRequestHelperTest {

    @Test
    public void hasDcqlQueryReturnsTrueWhenDcqlQueryPresent() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(mock(DCQLQuery.class));

        assertTrue(AuthorizationRequestHelper.hasDcqlQuery(dcqlRequest));
    }

    @Test
    public void hasDcqlQueryReturnsFalseWhenDcqlQueryMissing() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(null);

        assertFalse(AuthorizationRequestHelper.hasDcqlQuery(dcqlRequest));
    }

    @Test
    public void hasDcqlQueryReturnsFalseForPresentationExchangeRequest() {
        AuthorizationRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);

        assertFalse(AuthorizationRequestHelper.hasDcqlQuery(peRequest));
    }

    @Test
    public void resolveSpecVersionUsesDcqlQueryPresence() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(mock(DCQLQuery.class));
        AuthorizationRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);

        assertEquals(SpecVersion.V1, AuthorizationRequestHelper.resolveSpecVersion(dcqlRequest));
        assertEquals(SpecVersion.DRAFT_23, AuthorizationRequestHelper.resolveSpecVersion(peRequest));
    }

    @Test
    public void resolveSpecVersionTreatsMissingDcqlQueryAsDraft23() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(null);

        assertEquals(SpecVersion.DRAFT_23, AuthorizationRequestHelper.resolveSpecVersion(dcqlRequest));
    }

    @Test
    public void extractDcqlQueryReturnsQueryForDcqlRequest() {
        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(dcqlQuery);

        assertEquals(dcqlQuery, AuthorizationRequestHelper.extractDcqlQuery(dcqlRequest));
    }

    @Test
    public void extractDcqlQueryReturnsNullForPresentationExchangeRequest() {
        AuthorizationRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);

        assertNull(AuthorizationRequestHelper.extractDcqlQuery(peRequest));
    }
}
