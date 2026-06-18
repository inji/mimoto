package io.mosip.mimoto.dto.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.DcqlCredentialSelection;
import io.mosip.mimoto.dto.SelectedCredentials;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SelectedCredentialsDeserializer extends JsonDeserializer<SelectedCredentials> {

    @Override
    public SelectedCredentials deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException {
        JsonNode node = parser.getCodec().readTree(parser);
        if (!node.isArray()) {
            throw ctxt.weirdStringException(node.toString(), SelectedCredentials.class,
                    "selectedCredentials must be a JSON array");
        }
        if (node.isEmpty()) {
            return SelectedCredentials.ofStrings(List.of());
        }

        if (node.get(0).isTextual()) {
            List<String> ids = new ArrayList<>();
            node.forEach(item -> ids.add(item.asText()));
            return SelectedCredentials.ofStrings(ids);
        }

        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        List<DcqlCredentialSelection> selections = new ArrayList<>();
        for (JsonNode item : node) {
            selections.add(mapper.treeToValue(item, DcqlCredentialSelection.class));
        }
        return SelectedCredentials.ofDcql(selections);
    }
}
