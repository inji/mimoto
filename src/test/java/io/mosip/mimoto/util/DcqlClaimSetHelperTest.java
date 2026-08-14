package io.mosip.mimoto.util;

import com.jayway.jsonpath.JsonPath;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DcqlClaimSetHelperTest {

    @Test
    public void should_returnFalse_when_claimsEmptyButClaimSetsPresent() {
        CredentialQuery query = mock(CredentialQuery.class);
        when(query.getClaims()).thenReturn(List.of());
        when(query.getClaimSets()).thenReturn(List.of(List.of("age-above-18")));

        VCCredentialResponse vc = mock(VCCredentialResponse.class);

        assertFalse(DcqlClaimSetHelper.matchesClaims(query, vc, (ignored, claim) -> true));
    }

    @Test
    public void should_rejectClaimSet_when_containsUnknownClaimIds() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(query.getClaims()).thenReturn(List.of(ageClaim));

        VCCredentialResponse vc = mock(VCCredentialResponse.class);

        assertFalse(DcqlClaimSetHelper.satisfiesClaimSet(
                query, vc, List.of("age-above-18", "unknown-claim"), (ignored, claim) -> true));
    }

    @Test
    public void should_rejectClaimSet_when_containsOnlyUnknownClaimIds() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(query.getClaims()).thenReturn(List.of(ageClaim));

        VCCredentialResponse vc = mock(VCCredentialResponse.class);

        assertFalse(DcqlClaimSetHelper.satisfiesClaimSet(
                query, vc, List.of("unknown-claim"), (ignored, claim) -> true));
    }

    @Test
    public void should_returnEmptyPaths_when_anyClaimIdUnknown() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(query.getClaims()).thenReturn(List.of(ageClaim));

        assertTrue(DcqlClaimSetHelper.resolveClaimPaths(query, List.of("unknown-claim")).isEmpty());
        assertTrue(DcqlClaimSetHelper.resolveClaimPaths(
                query, List.of("age-above-18", "unknown-claim")).isEmpty());
    }

    @Test
    public void should_matchClaims_when_anyClaimSetSatisfied() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(ageClaim.getValues()).thenReturn(List.of(new ClaimValue.BoolValue(true)));
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(dobClaim.getPath()).thenReturn(List.of("dateOfBirth"));
        when(dobClaim.getValues()).thenReturn(null);

        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));
        when(query.getClaimSets()).thenReturn(List.of(
                List.of("age-above-18"),
                List.of("date-of-birth")));

        VCCredentialResponse vc = mock(VCCredentialResponse.class);

        assertTrue(DcqlClaimSetHelper.matchesClaims(query, vc, (ignored, claim) -> {
            if ("age-above-18".equals(claim.getId())) {
                return false;
            }
            return "date-of-birth".equals(claim.getId());
        }));
    }

    @Test
    public void should_requireAllClaims_when_claimSetsAbsent() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));
        when(query.getClaimSets()).thenReturn(null);

        VCCredentialResponse vc = mock(VCCredentialResponse.class);

        assertFalse(DcqlClaimSetHelper.matchesClaims(query, vc, (ignored, claim) ->
                "age-above-18".equals(claim.getId())));
    }

    @Test
    public void should_acceptSelection_when_matchesExactOption() {
        List<List<String>> claimSets = List.of(
                List.of("age-above-18"),
                List.of("date-of-birth"));
        assertTrue(DcqlClaimSetHelper.isValidClaimSetSelection(claimSets, List.of("date-of-birth")));
        assertFalse(DcqlClaimSetHelper.isValidClaimSetSelection(claimSets, List.of("age-above-18", "date-of-birth")));
    }

    @Test
    public void should_acceptSelection_when_claimIdOrderDiffers() {
        List<List<String>> claimSets = List.of(
                List.of("given-name", "family-name", "age-above-18"),
                List.of("date-of-birth"));
        assertTrue(DcqlClaimSetHelper.isValidClaimSetSelection(
                claimSets, List.of("age-above-18", "given-name", "family-name")));
        assertFalse(DcqlClaimSetHelper.isValidClaimSetSelection(
                claimSets, List.of("given-name", "family-name")));
    }

    @Test
    public void should_rejectSelection_when_claimIdsDuplicated() {
        List<List<String>> claimSets = List.of(List.of("given-name", "family-name"));
        assertFalse(DcqlClaimSetHelper.isValidClaimSetSelection(
                claimSets, List.of("given-name", "given-name")));
    }

    @Test
    public void should_quoteDottedSegments_when_buildingJsonPath() {
        Map<String, Object> payload = Map.of(
                "org.iso.18013.5.1", Map.of("family_name", "Doe"));

        String dottedKeyPath = DcqlClaimSetHelper.buildJsonPath(List.of("org.iso.18013.5.1"));
        String nestedDottedPath = DcqlClaimSetHelper.buildJsonPath(
                List.of("credentialSubject", "org.iso.18013.5.1", "family_name"));

        assertEquals("$['org.iso.18013.5.1']", dottedKeyPath);
        assertEquals(Map.of("family_name", "Doe"), JsonPath.read(payload, dottedKeyPath));
        assertEquals("$.credentialSubject['org.iso.18013.5.1'].family_name", nestedDottedPath);

        Map<String, Object> nestedPayload = Map.of(
                "credentialSubject", Map.of("org.iso.18013.5.1", Map.of("family_name", "Doe")));
        assertEquals("Doe", JsonPath.read(nestedPayload, nestedDottedPath));
    }
    @Test
    public void should_keepDotSeparatedSegments_when_buildingJsonPathForSimpleKeys() {
        assertEquals("$.credentialSubject.dateOfBirth",
                DcqlClaimSetHelper.buildJsonPath(List.of("credentialSubject", "dateOfBirth")));
    }

    @Test
    public void should_quoteDottedNestedSegments_when_buildingClaimPath() {
        assertEquals("org.iso.18013.5.1",
                DcqlClaimSetHelper.buildClaimPath(List.of("org.iso.18013.5.1")));
        assertEquals("credentialSubject['org.iso.18013.5.1'].family_name",
                DcqlClaimSetHelper.buildClaimPath(
                        List.of("credentialSubject", "org.iso.18013.5.1", "family_name")));
    }

    @Test
    public void should_useBracketSafeSegments_when_resolvingJsonPaths() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery mdlClaim = mock(ClaimsQuery.class);
        when(mdlClaim.getId()).thenReturn("family-name");
        when(mdlClaim.getPath()).thenReturn(List.of("org.iso.18013.5.1", "family_name"));
        when(query.getClaims()).thenReturn(List.of(mdlClaim));

        assertEquals(List.of("$['org.iso.18013.5.1'].family_name"),
                DcqlClaimSetHelper.resolveJsonPaths(query, List.of("family-name")));
    }

    @Test
    public void should_mapClaimIdsToPaths_when_resolvingClaimPaths() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(dobClaim.getPath()).thenReturn(List.of("dateOfBirth"));
        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));

        assertEquals(List.of("age_above_18"),
                DcqlClaimSetHelper.resolveClaimPaths(query, List.of("age-above-18")));
    }

    @Test
    public void should_pickFirstClaimSet_when_disclosurePresent() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(dobClaim.getPath()).thenReturn(List.of("dateOfBirth"));
        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));
        when(query.getClaimSets()).thenReturn(List.of(
                List.of("age-above-18"),
                List.of("date-of-birth")));

        // age_above_18 is public (no disclosure); dateOfBirth IS selectively disclosable
        List<String> resolved = DcqlClaimSetHelper.resolveClaimIdsForSubmission(
                query, null, path -> path.equals("dateOfBirth"));

        assertEquals(List.of("date-of-birth"), resolved);
    }

    @Test
    public void should_returnEmpty_when_allClaimsArePublic() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(dobClaim.getPath()).thenReturn(List.of("dateOfBirth"));
        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));
        when(query.getClaimSets()).thenReturn(List.of(
                List.of("age-above-18"),
                List.of("date-of-birth")));

        // Both are public — no SD filtering needed
        List<String> resolved = DcqlClaimSetHelper.resolveClaimIdsForSubmission(
                query, null, path -> false);

        assertTrue(resolved.isEmpty());
    }

    @Test
    public void should_honourExplicitSelectedClaimIds_when_resolvingForSubmission() {
        CredentialQuery query = mock(CredentialQuery.class);
        ClaimsQuery ageClaim = mock(ClaimsQuery.class);
        ClaimsQuery dobClaim = mock(ClaimsQuery.class);
        when(ageClaim.getId()).thenReturn("age-above-18");
        when(ageClaim.getPath()).thenReturn(List.of("age_above_18"));
        when(dobClaim.getId()).thenReturn("date-of-birth");
        when(dobClaim.getPath()).thenReturn(List.of("dateOfBirth"));
        when(query.getClaims()).thenReturn(List.of(ageClaim, dobClaim));
        when(query.getClaimSets()).thenReturn(List.of(
                List.of("age-above-18"),
                List.of("date-of-birth")));

        List<String> resolved = DcqlClaimSetHelper.resolveClaimIdsForSubmission(
                query, List.of("date-of-birth"), path -> false);

        assertEquals(List.of("date-of-birth"), resolved);
    }

    @Test
    public void should_matchBooleanAndString_when_comparingDcqlValues() {
        assertTrue(DcqlClaimSetHelper.dcqlValueMatches(true, new ClaimValue.BoolValue(true)));
        assertTrue(DcqlClaimSetHelper.dcqlValueMatches("yes", new ClaimValue.StringValue("yes")));
        assertFalse(DcqlClaimSetHelper.dcqlValueMatches(null, new ClaimValue.StringValue("yes")));
    }
}
