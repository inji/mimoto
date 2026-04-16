package io.mosip.mimoto.constant;

import lombok.Getter;

@Getter
public enum VCSpecificationVersion {
    DRAFT_13(VCSpecificationVersion.DRAFT_13_VERSION), V1(VCSpecificationVersion.V1_VERSION);

    public static final String DRAFT_13_VERSION = "draft-13";
    public static final String V1_VERSION = "v1";

    private final String version;

    VCSpecificationVersion(String version) {
        this.version = version;
    }
}
