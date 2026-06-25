package io.mosip.mimoto.util;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SelectedSdClaimsMergeUtilTest {

    @Test
    public void mergePathsUnionsDisclosurePathsForSameCredential() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsMergeUtil.mergePaths(merged, "cred-1", List.of("email"));
        SelectedSdClaimsMergeUtil.mergePaths(merged, "cred-1", List.of("phone"));

        assertEquals(List.of("email", "phone"), merged.get("cred-1"));
    }

    @Test
    public void mergePathsDeduplicatesPathsPreservingOrder() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsMergeUtil.mergePaths(merged, "cred-1", List.of("email", "phone"));
        SelectedSdClaimsMergeUtil.mergePaths(merged, "cred-1", List.of("phone", "address"));

        assertEquals(List.of("email", "phone", "address"), merged.get("cred-1"));
    }

    @Test
    public void mergeIntoUnionsAcrossMaps() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsMergeUtil.mergeInto(merged, Map.of("cred-1", List.of("email")));
        SelectedSdClaimsMergeUtil.mergeInto(merged, Map.of("cred-1", List.of("phone"), "cred-2", List.of("name")));

        assertEquals(List.of("email", "phone"), merged.get("cred-1"));
        assertEquals(List.of("name"), merged.get("cred-2"));
    }

    @Test
    public void mergeIntoIgnoresNullSource() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsMergeUtil.mergeInto(merged, null);
        assertNull(merged.get("cred-1"));
    }
}
