package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.dcql.evaluator.ClaimFailure;
import io.mosip.openID4VP.dcql.evaluator.DCQLEvaluationErrorCodes;
import io.mosip.openID4VP.dcql.evaluator.QueryMatchResult;
import io.mosip.openID4VP.helper.DCQLHelper;
import io.mosip.openID4VP.wallet.Credential;
import org.junit.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DcqlMatchingHelperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DCQLHelper dcqlHelper = new DCQLHelper();

    @Test
    public void toLibraryCredential_mapsLdpVcMapPayload() {
        DecryptedCredentialDTO dto = walletCredential("cred-1", CredentialFormat.LDP_VC.getFormat(),
                Map.of("credentialSubject", Map.of("id", "did:example:holder", "name", "Alice")));

        Credential credential = DcqlMatchingHelper.toLibraryCredential(dto, objectMapper);

        assertNotNull(credential);
        assertEquals(FormatType.LDP_VC, credential.getFormat());
        assertEquals("cred-1", credential.getCredentialId());
    }

    @Test
    public void toLibraryCredential_mapsSdJwtStringPayload() throws Exception {
        String token = buildSdJwtToken(Map.of("vct", "https://example.com/employee", "cnf", Map.of("kid", "k1")));
        DecryptedCredentialDTO dto = walletCredential("cred-2", CredentialFormat.DC_SD_JWT.getFormat(), token);

        Credential credential = DcqlMatchingHelper.toLibraryCredential(dto, objectMapper);

        assertNotNull(credential);
        assertEquals(FormatType.DC_SD_JWT, credential.getFormat());
    }

    @Test
    public void libraryEvaluation_rejectsSdJwtWithoutCnfWhenBindingRequired() throws Exception {
        String token = buildSdJwtToken(Map.of("vct", "https://example.com/employee"));
        DecryptedCredentialDTO dto = walletCredential("cred-3", CredentialFormat.VC_SD_JWT.getFormat(), token);

        CredentialQuery query = new CredentialQuery(
                "employee-card",
                CredentialFormat.VC_SD_JWT.getFormat(),
                false,
                Map.of("vct_values", List.of("https://example.com/employee")),
                true,
                null,
                null);
        DCQLQuery dcqlQuery = new DCQLQuery(List.of(query), null);

        var result = dcqlHelper.getMatchingCredentials(
                List.of(DcqlMatchingHelper.toLibraryCredential(dto, objectMapper)), dcqlQuery);

        assertFalse(result.getSuccess());
        assertTrue(result.getQueryMatches().get("employee-card").getMatchingCredentials() == null
                || result.getQueryMatches().get("employee-card").getMatchingCredentials().isEmpty());
    }

    @Test
    public void libraryEvaluation_matchesSdJwtWhenQueryUsesAlternateSdJwtFormat() throws Exception {
        String token = buildSdJwtToken(Map.of("vct", "https://example.com/employee", "cnf", Map.of("kid", "k1")));
        DecryptedCredentialDTO dto = walletCredential("cred-4", CredentialFormat.VC_SD_JWT.getFormat(), token);

        CredentialQuery query = new CredentialQuery(
                "employee-card",
                CredentialFormat.DC_SD_JWT.getFormat(),
                false,
                Map.of(),
                false,
                null,
                null);
        DCQLQuery dcqlQuery = new DCQLQuery(List.of(query), null);

        var result = dcqlHelper.getMatchingCredentials(
                DcqlMatchingHelper.constructCredentialWithCredentialFormat(List.of(dto), objectMapper), dcqlQuery);

        assertTrue(result.getSuccess());
        assertEquals("cred-4", result.getQueryMatches().get("employee-card").getMatchingCredentials().get(0).getCredentialId());
    }

    @Test
    public void resolveMissingClaims_usesFailedClaimPathsFromLibraryResult() {
        CredentialQuery query = new CredentialQuery(
                "age-proof",
                CredentialFormat.DC_SD_JWT.getFormat(),
                false,
                Map.of(),
                false,
                List.of(new ClaimsQuery("age-above-18", List.of("age_above_18"), List.of(new ClaimValue.BoolValue(true)))),
                null);
        QueryMatchResult queryMatch = new QueryMatchResult(
                null,
                List.of(new ClaimFailure(
                        new ClaimsQuery("age-above-18", List.of("age_above_18"), null),
                        DCQLEvaluationErrorCodes.CLAIM_UNAVAILABLE)),
                DCQLEvaluationErrorCodes.REQUIRED_CLAIMS_NOT_SATISFIED,
                false);

        Set<String> missingClaims = DcqlMatchingHelper.resolveMissingClaims(query, queryMatch);

        assertEquals(Set.of("age_above_18"), missingClaims);
    }

    private static DecryptedCredentialDTO walletCredential(String id, String format, Object payload) {
        DecryptedCredentialDTO dto = new DecryptedCredentialDTO();
        dto.setId(id);
        dto.setCredential(VCCredentialResponse.builder().format(format).credential(payload).build());
        return dto;
    }

    private static String buildSdJwtToken(Map<String, Object> payload) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(mapper.writeValueAsBytes(Map.of("alg", "none")));
        String encodedPayload = encoder.encodeToString(mapper.writeValueAsBytes(payload));
        return header + "." + encodedPayload + ".signature";
    }
}
