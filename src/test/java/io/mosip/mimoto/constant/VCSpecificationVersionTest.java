package io.mosip.mimoto.constant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VCSpecificationVersionTest {

    @Test
    void shouldReturnCorrectVersionStringForDraft13() {
        assertEquals("draft-13", VCSpecificationVersion.DRAFT_13.getVersion());
    }

    @Test
    void shouldReturnCorrectVersionStringForV1() {
        assertEquals("v1", VCSpecificationVersion.V1.getVersion());
    }

    @Test
    void shouldHaveTwoEnumValues() {
        assertEquals(2, VCSpecificationVersion.values().length);
    }

    @Test
    void shouldResolveFromName() {
        assertEquals(VCSpecificationVersion.DRAFT_13, VCSpecificationVersion.valueOf("DRAFT_13"));
        assertEquals(VCSpecificationVersion.V1, VCSpecificationVersion.valueOf("V1"));
    }
}
