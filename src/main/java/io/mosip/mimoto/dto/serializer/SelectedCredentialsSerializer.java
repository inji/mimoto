package io.mosip.mimoto.dto.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.mosip.mimoto.dto.SelectedCredentials;

import java.io.IOException;

public class SelectedCredentialsSerializer extends StdSerializer<SelectedCredentials> {

    public SelectedCredentialsSerializer() {
        super(SelectedCredentials.class);
    }

    @Override
    public void serialize(SelectedCredentials value, JsonGenerator gen, SerializerProvider provider)
            throws IOException {
        gen.writeStartArray();
        if (value.isDcql()) {
            for (var selection : value.getDcqlSelections()) {
                gen.writeObject(selection);
            }
        } else if (value.getCredentialIds() != null) {
            for (String id : value.getCredentialIds()) {
                gen.writeString(id);
            }
        }
        gen.writeEndArray();
    }
}
