package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DcqlClaimSetHelperTest {

    @Test
    public void matchesClaimsWhenAnyClaimSetSatisfied() {
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
    public void matchesClaimsRequiresAllClaimsWhenClaimSetsAbsent() {
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
    public void isValidClaimSetSelectionMatchesExactOption() {
        List<List<String>> claimSets = List.of(
                List.of("age-above-18"),
                List.of("date-of-birth"));
        assertTrue(DcqlClaimSetHelper.isValidClaimSetSelection(claimSets, List.of("date-of-birth")));
        assertFalse(DcqlClaimSetHelper.isValidClaimSetSelection(claimSets, List.of("age-above-18", "date-of-birth")));
    }

    @Test
    public void resolveClaimPathsMapsClaimIdsToPaths() {
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
    public void resolveClaimIdsForSubmissionPicksFirstClaimSetWithDisclosure() {
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
    public void resolveClaimIdsForSubmissionReturnsEmptyWhenAllClaimsArePublic() {
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
    public void resolveClaimIdsForSubmissionHonoursExplicitSelectedClaimIds() {
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
    public void dcqlValueMatchesBooleanAndString() {
        assertTrue(DcqlClaimSetHelper.dcqlValueMatches(true, new ClaimValue.BoolValue(true)));
        assertTrue(DcqlClaimSetHelper.dcqlValueMatches("yes", new ClaimValue.StringValue("yes")));
    }
}
