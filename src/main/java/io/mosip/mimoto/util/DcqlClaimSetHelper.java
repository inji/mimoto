package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Shared DCQL {@code claim_sets} logic for credential matching and presentation submission.
 * A {@code claim_sets} entry is satisfied when every claim id in that set matches the credential.
 * The query is satisfied when any claim set matches (OR).
 */
public final class DcqlClaimSetHelper {

    private static final String JSON_PATH_PREFIX = "$.";

    private DcqlClaimSetHelper() {
    }

    public static boolean hasClaimSets(CredentialQuery credentialQuery) {
        return credentialQuery.getClaimSets() != null && !credentialQuery.getClaimSets().isEmpty();
    }

    public static boolean matchesClaims(CredentialQuery credentialQuery, VCCredentialResponse vc,
                                        BiPredicate<VCCredentialResponse, ClaimsQuery> claimMatcher) {
        if (credentialQuery.getClaims() == null || credentialQuery.getClaims().isEmpty()) {
            return true;
        }
        if (hasClaimSets(credentialQuery)) {
            return credentialQuery.getClaimSets().stream()
                    .anyMatch(claimIds -> satisfiesClaimSet(credentialQuery, vc, claimIds, claimMatcher));
        }
        return credentialQuery.getClaims().stream()
                .allMatch(claimQuery -> claimMatcher.test(vc, claimQuery));
    }

    public static boolean satisfiesClaimSet(CredentialQuery credentialQuery, VCCredentialResponse vc,
                                            List<String> claimIds,
                                            BiPredicate<VCCredentialResponse, ClaimsQuery> claimMatcher) {
        if (claimIds == null || claimIds.isEmpty()) {
            return false;
        }
        Map<String, ClaimsQuery> claimsById = indexClaimsById(credentialQuery);
        return claimIds.stream()
                .map(claimsById::get)
                .filter(Objects::nonNull)
                .allMatch(claimQuery -> claimMatcher.test(vc, claimQuery));
    }

    public static boolean isValidClaimSetSelection(List<List<String>> claimSets, List<String> selectedClaimIds) {
        if (selectedClaimIds == null || selectedClaimIds.isEmpty() || claimSets == null) {
            return false;
        }
        List<String> normalized = normalizeClaimIds(selectedClaimIds);
        return claimSets.stream()
                .map(DcqlClaimSetHelper::normalizeClaimIds)
                .anyMatch(option -> option.equals(normalized));
    }

    /**
     * Resolves claim ids for submission.
     * <p>
     * Iterates {@code claim_sets} in order and returns the first set whose every claim path
     * has an actual SD disclosure on the credential (checked via {@code hasDisclosure}).
     * Returns an empty list when no claim set has any disclosure — this means all claims in
     * every set are public payload claims and no SD filtering is needed.
     * </p>
     */
    public static List<String> resolveClaimIdsForSubmission(CredentialQuery credentialQuery,
                                                            List<String> selectedClaimIds,
                                                            Predicate<String> hasDisclosure) {
        if (!hasClaimSets(credentialQuery)) {
            return Collections.emptyList();
        }
        if (selectedClaimIds != null && !selectedClaimIds.isEmpty()) {
            return normalizeClaimIds(selectedClaimIds);
        }
        for (List<String> claimSet : credentialQuery.getClaimSets()) {
            List<String> normalized = normalizeClaimIds(claimSet);
            List<String> paths = resolveClaimPaths(credentialQuery, normalized);
            if (!paths.isEmpty() && paths.stream().allMatch(hasDisclosure)) {
                return normalized;
            }
        }
        // No claim set resolved to an SD disclosure — all claims are public; no filtering needed.
        return Collections.emptyList();
    }

    /**
     * Maps DCQL claim ids to credential claim paths (without {@code $.} prefix).
     */
    public static List<String> resolveClaimPaths(CredentialQuery credentialQuery, List<String> claimIds) {
        if (claimIds == null || claimIds.isEmpty()) {
            return Collections.emptyList();
        }
        Map<String, ClaimsQuery> claimsById = indexClaimsById(credentialQuery);
        List<String> paths = new ArrayList<>();
        for (String claimId : claimIds) {
            ClaimsQuery claimQuery = claimsById.get(claimId);
            if (claimQuery == null || claimQuery.getPath() == null || claimQuery.getPath().isEmpty()) {
                continue;
            }
            paths.add(claimQuery.getPath().stream()
                    .map(Object::toString)
                    .collect(Collectors.joining(".")));
        }
        return paths;
    }

    public static List<String> resolveJsonPaths(CredentialQuery credentialQuery, List<String> claimIds) {
        return resolveClaimPaths(credentialQuery, claimIds).stream()
                .map(path -> JSON_PATH_PREFIX + path)
                .collect(Collectors.toList());
    }

    private static Map<String, ClaimsQuery> indexClaimsById(CredentialQuery credentialQuery) {
        if (credentialQuery.getClaims() == null) {
            return Collections.emptyMap();
        }
        Map<String, ClaimsQuery> claimsById = new LinkedHashMap<>();
        for (ClaimsQuery claimQuery : credentialQuery.getClaims()) {
            if (claimQuery.getId() != null) {
                claimsById.putIfAbsent(claimQuery.getId(), claimQuery);
            }
        }
        return claimsById;
    }

    private static List<String> normalizeClaimIds(List<String> claimIds) {
        return claimIds.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toList());
    }

    public static boolean dcqlValueMatches(Object actual, ClaimValue expected) {
        if (expected instanceof ClaimValue.StringValue sv) {
            return sv.getValue().equals(actual.toString());
        }
        if (expected instanceof ClaimValue.LongValue lv) {
            if (actual instanceof Number number) {
                return lv.getValue() == number.longValue();
            }
            return false;
        }
        if (expected instanceof ClaimValue.BoolValue bv) {
            if (actual instanceof Boolean bool) {
                return bv.getValue() == bool;
            }
            return false;
        }
        return false;
    }

    public static Set<String> pathsForClaimIds(CredentialQuery credentialQuery, List<String> claimIds) {
        return new LinkedHashSet<>(resolveJsonPaths(credentialQuery, claimIds));
    }
}
