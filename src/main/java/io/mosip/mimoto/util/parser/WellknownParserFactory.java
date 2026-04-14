package io.mosip.mimoto.util.parser;

import io.mosip.mimoto.constant.VCSpecificationVersion;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class WellknownParserFactory {

    private final Map<VCSpecificationVersion, WellknownResponseParser> parsers;

    public WellknownParserFactory(List<WellknownResponseParser> parserList) {
        this.parsers = parserList.stream()
                .collect(Collectors.toMap(
                        WellknownResponseParser::getSupportedVersion,
                        Function.identity()
                ));
    }

    public WellknownResponseParser getParser(VCSpecificationVersion version) {
        WellknownResponseParser parser = parsers.get(version);
        if (parser == null) {
            throw new IllegalArgumentException("No wellknown parser found for version: " + version);
        }
        return parser;
    }
}
