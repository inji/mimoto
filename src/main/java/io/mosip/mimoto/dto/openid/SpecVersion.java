package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.annotation.JsonValue;

public enum SpecVersion {
    V1_0("v1"),
    DRAFT_23("draft23");

    private final String version;

    SpecVersion(String version) {
        this.version = version;
    }

    @JsonValue
    public String getVersion() {
        return version;
    }
}
