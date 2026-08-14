package io.mosip.mimoto.util;

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
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
    public void should_returnTrue_when_dcqlQueryPresent() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(mock(DCQLQuery.class));

        assertTrue(AuthorizationRequestHelper.hasDcqlQuery(dcqlRequest));
    }

    @Test
    public void should_returnFalse_when_dcqlQueryMissing() {
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(null);

        assertFalse(AuthorizationRequestHelper.hasDcqlQuery(dcqlRequest));
    }

    @Test
    public void should_returnFalse_when_presentationExchangeRequest() {
        AuthorizationRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);

        assertFalse(AuthorizationRequestHelper.hasDcqlQuery(peRequest));
    }

    @Test
    public void should_returnDcqlQuery_when_dcqlRequest() {
        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(dcqlQuery);

        assertEquals(dcqlQuery, AuthorizationRequestHelper.extractDcqlQuery(dcqlRequest));
    }

    @Test
    public void should_returnNull_when_presentationExchangeRequest() {
        AuthorizationRequest peRequest = mock(AuthorizationPresentationExchangeRequest.class);

        assertNull(AuthorizationRequestHelper.extractDcqlQuery(peRequest));
    }
}
