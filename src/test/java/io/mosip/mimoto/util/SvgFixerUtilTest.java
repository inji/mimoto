package io.mosip.mimoto.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SvgFixerUtilTest {

    private final SvgFixerUtil util = new SvgFixerUtil();

    @Test
    void testAddMissingOffsetToStopElements_withMissingOffset() {
        String input = "<svg><stop/></svg>";
        String expected = "<svg><stop offset=\"0\" /></svg>";
        Assertions.assertEquals(expected, util.addMissingOffsetToStopElements(input));
    }

    @Test
    void testAddMissingOffsetToStopElements_withExistingOffset() {
        String input = "<svg><stop offset=\"0.5\"/></svg>";
        String expected = "<svg><stop offset=\"0.5\"/></svg>";
        Assertions.assertEquals(expected, util.addMissingOffsetToStopElements(input));
    }

    @Test
    void testAddMissingOffsetToStopElements_multipleStops() {
        String input = "<svg><stop/><stop offset=\"0.2\"/><stop/></svg>";
        String expected = "<svg><stop offset=\"0\" /><stop offset=\"0.2\"/><stop offset=\"0\" /></svg>";
        Assertions.assertEquals(expected, util.addMissingOffsetToStopElements(input));
    }

    @Test
    void testAddMissingOffsetToStopElements_nullInput() {
        Assertions.assertNull(util.addMissingOffsetToStopElements(null));
    }
}