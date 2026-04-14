package io.mosip.mimoto.constant;

import lombok.Getter;

@Getter
public enum VCSpecificationVersion {
    DRAFT_13("draft-13"),
    V1("v1");

    private final String version;

    VCSpecificationVersion(String version) {
        this.version = version;
    }
}
