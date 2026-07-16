package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import io.mosip.openID4VP.constants.SpecVersion;

import java.io.IOException;

class SpecVersionSerializer extends JsonSerializer<SpecVersion> {

    @Override
    public void serialize(SpecVersion value, JsonGenerator generator, SerializerProvider serializers) throws IOException {
        generator.writeString(value == SpecVersion.DRAFT_23 ? "draft23" : "v1");
    }
}
