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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Shared DCQL {@code claim_sets} logic for credential matching and presentation submission.
 * A {@code claim_sets} entry is satisfied when every claim id in that set matches the credential.
 * The query is satisfied when any claim set matches (OR).
 */
public final class DcqlClaimSetHelper {

    /** Simple JSON keys use dot notation; keys with dots/hyphens need bracket notation (e.g. {@code org.iso.18013.5.1}). */
    private static final Pattern SIMPLE_PATH_SEGMENT = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");

    private DcqlClaimSetHelper() {
    }

    /**
     * Builds a Jayway JSONPath from DCQL path segments, quoting segments that are not simple identifiers.
     */
    public static String buildJsonPath(List<?> pathSegments) {
        if (pathSegments == null || pathSegments.isEmpty()) {
            return "$";
        }
        StringBuilder jsonPath = new StringBuilder("$");
        appendPathSegments(jsonPath, pathSegments);
        return jsonPath.toString();
    }

    /**
     * Builds a credential claim path (without {@code $.}) for SD-JWT lookup and missing-claim reporting.
     */
    public static String buildClaimPath(List<?> pathSegments) {
        if (pathSegments == null || pathSegments.isEmpty()) {
            return "";
        }
        StringBuilder claimPath = new StringBuilder(pathSegments.get(0).toString());
        if (pathSegments.size() > 1) {
            appendPathSegments(claimPath, pathSegments.subList(1, pathSegments.size()));
        }
        return claimPath.toString();
    }

    private static void appendPathSegments(StringBuilder path, List<?> pathSegments) {
        for (Object segment : pathSegments) {
            String value = segment.toString();
            if (SIMPLE_PATH_SEGMENT.matcher(value).matches()) {
                path.append('.').append(value);
            } else {
                path.append("['").append(escapePathSegment(value)).append("']");
            }
        }
    }

    private static String escapePathSegment(String segment) {
        return segment.replace("\\", "\\\\").replace("'", "\\'");
    }

    public static boolean hasClaimSets(CredentialQuery credentialQuery) {
        return credentialQuery.getClaimSets() != null && !credentialQuery.getClaimSets().isEmpty();
    }

    public static boolean matchesClaims(CredentialQuery credentialQuery, VCCredentialResponse vc,
                                        BiPredicate<VCCredentialResponse, ClaimsQuery> claimMatcher) {
        boolean hasClaimSets = hasClaimSets(credentialQuery);
        List<ClaimsQuery> claims = credentialQuery.getClaims();
        boolean hasClaims = claims != null && !claims.isEmpty();

        if (!hasClaims) {
            return !hasClaimSets;
        }
        if (hasClaimSets) {
            return credentialQuery.getClaimSets().stream()
                    .anyMatch(claimIds -> satisfiesClaimSet(credentialQuery, vc, claimIds, claimMatcher));
        }
        return claims.stream()
                .allMatch(claimQuery -> claimMatcher.test(vc, claimQuery));
    }

    public static boolean satisfiesClaimSet(CredentialQuery credentialQuery, VCCredentialResponse vc,
                                            List<String> claimIds,
                                            BiPredicate<VCCredentialResponse, ClaimsQuery> claimMatcher) {
        if (claimIds == null || claimIds.isEmpty()) {
            return false;
        }
        Map<String, ClaimsQuery> claimsById = indexClaimsById(credentialQuery);
        for (String claimId : claimIds) {
            ClaimsQuery claimQuery = claimsById.get(claimId);
            if (claimQuery == null || !claimMatcher.test(vc, claimQuery)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidClaimSetSelection(List<List<String>> claimSets, List<String> selectedClaimIds) {
        if (selectedClaimIds == null || selectedClaimIds.isEmpty() || claimSets == null) {
            return false;
        }
        Set<String> selected = toUniqueClaimIdSet(selectedClaimIds);
        if (selected == null) {
            return false;
        }
        return claimSets.stream()
                .map(DcqlClaimSetHelper::toUniqueClaimIdSet)
                .filter(Objects::nonNull)
                .anyMatch(selected::equals);
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
            if (paths.size() != normalized.size()) {
                continue;
            }
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
                return Collections.emptyList();
            }
            paths.add(buildClaimPath(claimQuery.getPath()));
        }
        return paths;
    }

    public static List<String> resolveJsonPaths(CredentialQuery credentialQuery, List<String> claimIds) {
        if (claimIds == null || claimIds.isEmpty()) {
            return Collections.emptyList();
        }
        Map<String, ClaimsQuery> claimsById = indexClaimsById(credentialQuery);
        List<String> paths = new ArrayList<>();
        for (String claimId : claimIds) {
            ClaimsQuery claimQuery = claimsById.get(claimId);
            if (claimQuery == null || claimQuery.getPath() == null || claimQuery.getPath().isEmpty()) {
                return Collections.emptyList();
            }
            paths.add(buildJsonPath(claimQuery.getPath()));
        }
        return paths;
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

    /**
     * Normalizes claim ids and returns a set when the input has no duplicates; otherwise {@code null}.
     */
    private static Set<String> toUniqueClaimIdSet(List<String> claimIds) {
        List<String> normalized = normalizeClaimIds(claimIds);
        Set<String> unique = new LinkedHashSet<>(normalized);
        return unique.size() == normalized.size() ? unique : null;
    }

    public static boolean dcqlValueMatches(Object actual, ClaimValue expected) {
        if (expected instanceof ClaimValue.StringValue sv) {
            return actual != null && sv.getValue().equals(actual.toString());
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
