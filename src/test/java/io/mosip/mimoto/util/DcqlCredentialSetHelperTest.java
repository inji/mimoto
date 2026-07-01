package io.mosip.mimoto.util;

import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DcqlCredentialSetHelperTest {

    @Test
    public void resolveEffectiveCredentialSetsReturnsExplicitSets() {
        CredentialSetQuery explicitSet = mock(CredentialSetQuery.class);
        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentialSets()).thenReturn(List.of(explicitSet));

        assertEquals(List.of(explicitSet), DcqlCredentialSetHelper.resolveEffectiveCredentialSets(dcqlQuery));
    }

    @Test
    public void resolveEffectiveCredentialSetsSynthesisesOneRequiredSetPerQueryWhenAbsent() {
        CredentialQuery governmentQuery = new CredentialQuery(
                "government-identity", "dc+sd-jwt", false, Map.of(), false, null, null);
        CredentialQuery ageQuery = new CredentialQuery(
                "age-proof", "dc+sd-jwt", false, Map.of(), false, null, null);
        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlQuery.getCredentialSets()).thenReturn(null);
        when(dcqlQuery.getCredentials()).thenReturn(List.of(governmentQuery, ageQuery));

        List<CredentialSetQuery> sets = DcqlCredentialSetHelper.resolveEffectiveCredentialSets(dcqlQuery);

        assertEquals(2, sets.size());
        assertTrue(sets.get(0).getRequired());
        assertEquals(List.of(List.of("government-identity")), sets.get(0).getOptions());
        assertTrue(sets.get(1).getRequired());
        assertEquals(List.of(List.of("age-proof")), sets.get(1).getOptions());
    }
}
