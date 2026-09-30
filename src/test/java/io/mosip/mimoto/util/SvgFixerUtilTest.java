package io.mosip.mimoto.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class SvgFixerUtilTest {

    private final SvgFixerUtil util = new SvgFixerUtil();

    @ParameterizedTest
    @CsvSource({
        "'<svg><stop/></svg>', '<svg><stop offset=\"0\" /></svg>'",
        "'<svg><stop offset=\"0.5\"/></svg>', '<svg><stop offset=\"0.5\"/></svg>'",
        "'<svg><stop/><stop offset=\"0.2\"/><stop/></svg>', '<svg><stop offset=\"0\" /><stop offset=\"0.2\"/><stop offset=\"0\" /></svg>'"
    })
    void addMissingOffsetToStopElementsHandlesVariousInputs(String input, String expected) {
        Assertions.assertEquals(expected, util.addMissingOffsetToStopElements(input));
    }

    @Test
    void testAddMissingOffsetToStopElements_nullInput() {
        Assertions.assertNull(util.addMissingOffsetToStopElements(null));
    }
}
