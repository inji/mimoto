package io.mosip.mimoto.util;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SelectedSdClaimsUtilTest {

    @Test
    public void should_unionDisclosurePaths_when_sameCredentialIsMerged() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsUtil.mergePaths(merged, "cred-1", List.of("email"));
        SelectedSdClaimsUtil.mergePaths(merged, "cred-1", List.of("phone"));

        assertEquals(List.of("email", "phone"), merged.get("cred-1"));
    }

    @Test
    public void should_deduplicatePaths_when_pathsOverlap() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsUtil.mergePaths(merged, "cred-1", List.of("email", "phone"));
        SelectedSdClaimsUtil.mergePaths(merged, "cred-1", List.of("phone", "address"));

        assertEquals(List.of("email", "phone", "address"), merged.get("cred-1"));
    }

    @Test
    public void should_unionCredentialMaps_when_sourcesContainMultipleCredentials() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsUtil.mergeInto(merged, Map.of("cred-1", List.of("email")));
        SelectedSdClaimsUtil.mergeInto(merged, Map.of("cred-1", List.of("phone"), "cred-2", List.of("name")));

        assertEquals(List.of("email", "phone"), merged.get("cred-1"));
        assertEquals(List.of("name"), merged.get("cred-2"));
    }

    @Test
    public void should_ignoreNullSource_when_mergingIntoTarget() {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        SelectedSdClaimsUtil.mergeInto(merged, null);
        assertNull(merged.get("cred-1"));
    }
}
