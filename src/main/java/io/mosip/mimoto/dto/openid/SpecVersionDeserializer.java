package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import io.mosip.openID4VP.constants.SpecVersion;

import java.io.IOException;

class SpecVersionDeserializer extends JsonDeserializer<SpecVersion> {

    @Override
    public SpecVersion deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        return switch (parser.getValueAsString()) {
            case "v1" -> SpecVersion.V1;
            case "draft23" -> SpecVersion.DRAFT_23;
            default -> throw new IllegalArgumentException("Unknown spec_version: " + parser.getValueAsString());
        };
    }
}
