package io.mosip.mimoto.dto.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.DcqlCredentialSelection;
import io.mosip.mimoto.dto.SelectedCredentials;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SelectedCredentialsDeserializer extends JsonDeserializer<SelectedCredentials> {

    private static final String HOMOGENEOUS_ARRAY_MESSAGE =
            "selectedCredentials must be either all credential ID strings or all DCQL selection objects";

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

        JsonNode first = node.get(0);
        if (first.isTextual()) {
            List<String> ids = new ArrayList<>();
            for (JsonNode item : node) {
                if (!item.isTextual()) {
                    throw JsonMappingException.from(parser, HOMOGENEOUS_ARRAY_MESSAGE);
                }
                ids.add(item.asText());
            }
            return SelectedCredentials.ofStrings(ids);
        }

        if (first.isObject()) {
            ObjectMapper mapper = (ObjectMapper) parser.getCodec();
            List<DcqlCredentialSelection> selections = new ArrayList<>();
            for (JsonNode item : node) {
                if (!item.isObject()) {
                    throw JsonMappingException.from(parser, HOMOGENEOUS_ARRAY_MESSAGE);
                }
                selections.add(mapper.treeToValue(item, DcqlCredentialSelection.class));
            }
            return SelectedCredentials.ofDcql(selections);
        }

        throw JsonMappingException.from(parser, HOMOGENEOUS_ARRAY_MESSAGE);
    }
}
