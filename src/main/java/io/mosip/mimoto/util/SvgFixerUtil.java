package io.mosip.mimoto.util;

import org.springframework.stereotype.Component;

@Component
public class SvgFixerUtil {

    // Adds missing offset attribute to <stop/> elements in SVG content
    public String addMissingOffsetToStopElements(String svgContent) {
        if (svgContent == null) return null;

        // Add offset="0" if missing in <stop> elements
        return svgContent.replaceAll(
                "<stop(?![^>]*offset=)",
                "<stop offset=\"0\" "
        );
    }
}