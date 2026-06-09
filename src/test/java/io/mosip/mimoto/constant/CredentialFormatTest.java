package io.mosip.mimoto.constant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialFormatTest {

    @Test
    void shouldReturnCorrectFormatStringForEachValue() {
        assertEquals("vc+sd-jwt", CredentialFormat.VC_SD_JWT.getFormat());
        assertEquals("dc+sd-jwt", CredentialFormat.DC_SD_JWT.getFormat());
        assertEquals("ldp_vc", CredentialFormat.LDP_VC.getFormat());
    }

    @Test
    void shouldHaveThreeEnumValues() {
        assertEquals(3, CredentialFormat.values().length);
    }

    @Test
    void fromStringShouldResolveEachFormatCaseInsensitively() {
        assertEquals(CredentialFormat.VC_SD_JWT, CredentialFormat.fromString("vc+sd-jwt"));
        assertEquals(CredentialFormat.DC_SD_JWT, CredentialFormat.fromString("dc+sd-jwt"));
        assertEquals(CredentialFormat.LDP_VC, CredentialFormat.fromString("ldp_vc"));
        // case-insensitive
        assertEquals(CredentialFormat.VC_SD_JWT, CredentialFormat.fromString("VC+SD-JWT"));
        assertEquals(CredentialFormat.DC_SD_JWT, CredentialFormat.fromString("DC+SD-JWT"));
    }

    @Test
    void fromStringShouldThrowForUnknownFormat() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> CredentialFormat.fromString("unknown_format"));
        assertEquals("Unknown credential format: unknown_format", exception.getMessage());
    }

    @Test
    void isSdJwtShouldBeTrueForBothSdJwtFormats() {
        assertTrue(CredentialFormat.isSdJwt("vc+sd-jwt"));
        assertTrue(CredentialFormat.isSdJwt("dc+sd-jwt"));
        // case-insensitive
        assertTrue(CredentialFormat.isSdJwt("VC+SD-JWT"));
        assertTrue(CredentialFormat.isSdJwt("DC+SD-JWT"));
    }

    @Test
    void isSdJwtShouldBeFalseForLdpVc() {
        assertFalse(CredentialFormat.isSdJwt("ldp_vc"));
    }

    @Test
    void isSdJwtShouldBeFalseForNull() {
        assertFalse(CredentialFormat.isSdJwt(null));
    }

    @Test
    void isSdJwtShouldBeFalseForUnknownFormat() {
        assertFalse(CredentialFormat.isSdJwt("mso_mdoc"));
    }
}