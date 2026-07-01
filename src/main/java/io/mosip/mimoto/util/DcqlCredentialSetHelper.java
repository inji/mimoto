package io.mosip.mimoto.util;

import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Shared DCQL {@code credential_sets} resolution for matching and submission validation.
 */
public final class DcqlCredentialSetHelper {

    private DcqlCredentialSetHelper() {
    }

    /**
     * Returns explicit {@code credential_sets} from the authorization request, or synthesises
     * one required set per credential query when absent (OpenID4VP / inji-openid4vp default).
     */
    public static List<CredentialSetQuery> resolveEffectiveCredentialSets(DCQLQuery dcqlQuery) {
        if (dcqlQuery.getCredentialSets() != null) {
            return dcqlQuery.getCredentialSets();
        }
        return dcqlQuery.getCredentials().stream()
                .map(DcqlCredentialSetHelper::syntheticSetForQuery)
                .collect(Collectors.toList());
    }

    private static CredentialSetQuery syntheticSetForQuery(CredentialQuery query) {
        return new CredentialSetQuery(List.of(List.of(query.getId())), true);
    }
}
