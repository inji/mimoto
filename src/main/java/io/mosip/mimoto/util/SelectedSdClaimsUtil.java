package io.mosip.mimoto.util;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Unions SD-JWT disclosure paths per credential ID when paths come from multiple sources
 * (top-level {@code selectedSdClaims}, nested DCQL selections, or {@code claim_sets} resolution).
 * Used by {@link io.mosip.mimoto.dto.SubmitPresentationRequestDTO#resolveEffectiveSelectedSdClaims()}
 * and {@link io.mosip.mimoto.service.impl.WalletPresentationServiceImpl} during DCQL submit.
 */
public final class SelectedSdClaimsUtil {

    private SelectedSdClaimsUtil() {
    }

    public static void mergeInto(Map<String, List<String>> target, Map<String, List<String>> source) {
        if (source == null) {
            return;
        }
        for (Map.Entry<String, List<String>> entry : source.entrySet()) {
            mergePaths(target, entry.getKey(), entry.getValue());
        }
    }

    public static void mergePaths(Map<String, List<String>> target, String credentialId, List<String> paths) {
        if (credentialId == null || paths == null || paths.isEmpty()) {
            return;
        }
        target.merge(credentialId, new ArrayList<>(paths), SelectedSdClaimsUtil::unionPaths);
    }

    private static List<String> unionPaths(List<String> existing, List<String> incoming) {
        LinkedHashSet<String> union = new LinkedHashSet<>(existing);
        union.addAll(incoming);
        return new ArrayList<>(union);
    }
}
