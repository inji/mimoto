package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.apache.commons.lang3.StringUtils;

import javax.xml.stream.XMLInputFactory;

/**
 * Reads issuer {@code <VCError><error/><error_description/></VCError>} bodies into the JSON
 * fields already used by credential response DTOs.
 */
public final class XmlErrorToJson {

    private static final XmlMapper XML_MAPPER = xmlMapper();

    private XmlErrorToJson() {
    }

    public static boolean isXml(String body) {
        return StringUtils.trimToEmpty(body).startsWith("<");
    }

    public static ObjectNode toJson(String body) throws Exception {
        if (!isXml(body)) {
            return null;
        }
        JsonNode parsed = XML_MAPPER.readTree(body);
        JsonNode fields = errorNode(parsed);
        if (fields instanceof ObjectNode objectNode) {
            return objectNode;
        }
        return null;
    }

    private static JsonNode errorNode(JsonNode parsed) {
        if (parsed != null && parsed.isObject() && hasError(parsed)) {
            return parsed;
        }
        if (parsed != null && parsed.size() == 1) {
            JsonNode child = parsed.elements().next();
            if (child.isObject() && hasError(child)) {
                return child;
            }
        }
        return null;
    }

    private static boolean hasError(JsonNode node) {
        return node.has("error") || node.has("error_description");
    }

    private static XmlMapper xmlMapper() {
        XMLInputFactory inputFactory = XMLInputFactory.newFactory();
        inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return new XmlMapper(new XmlFactory(inputFactory));
    }
}
