package io.mosip.mimoto.util;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Selective disclosure for mso_mdoc credentials: claim path helpers and the filter that keeps
 * only the selected issuer-signed items. An mdoc claim is one element inside one namespace, and
 * both parts are compared exactly (case sensitive), never as one dotted string, because
 * namespaces contain dots.
 */
@Slf4j
public final class MdocSelectiveDisclosureUtil {

    private static final String DOCUMENTS = "documents";
    private static final String DOC_TYPE = "docType";
    private static final String ISSUER_SIGNED = "issuerSigned";
    private static final String ISSUER_AUTH = "issuerAuth";
    private static final String NAME_SPACES = "nameSpaces";
    private static final String ELEMENT_IDENTIFIER = "elementIdentifier";
    private static final int COSE_SIGN1_PAYLOAD_INDEX = 2;
    private static final long ENCODED_CBOR_TAG = 24;

    /**
     * A selected mdoc claim, identified by its namespace and element identifier.
     */
    public record MdocClaim(String namespace, String elementIdentifier) {
    }

    private MdocSelectiveDisclosureUtil() {
    }

    /**
     * Builds the JSON path the wallet UI receives for an mdoc claim, e.g.
     * {@code $['org.iso.18013.5.1']['family_name']}.
     */
    public static String toJsonPath(String namespace, String elementIdentifier) {
        return "$['" + escape(namespace) + "']['" + escape(elementIdentifier) + "']";
    }

    /**
     * Parses a claim path into (namespace, elementIdentifier). Supported forms:
     * {@code org.iso.18013.5.1.given_name}, {@code org.iso.18013.5.1['given.name']},
     * {@code $['org.iso.18013.5.1']['given_name']} and {@code $['org.iso.18013.5.1'].given_name}.
     * The element is always the last segment, so the namespace may contain dots.
     *
     * @return the parsed claim, or null if the path does not name both a namespace and an element
     */
    public static MdocClaim parse(String claimPath) {
        if (claimPath == null || claimPath.isBlank()) {
            return null;
        }
        String path = claimPath.trim();
        if (path.startsWith("$")) {
            path = path.substring(1);
            if (path.startsWith(".")) {
                path = path.substring(1);
            }
        }

        String namespacePart;
        String element;
        if (path.endsWith("]")) {
            int open = findLastBracketOpen(path);
            if (open < 0) {
                return null;
            }
            element = unquoteBracket(path.substring(open));
            namespacePart = path.substring(0, open);
        } else {
            int lastDot = path.lastIndexOf('.');
            if (lastDot <= 0) {
                return null;
            }
            element = path.substring(lastDot + 1);
            namespacePart = path.substring(0, lastDot);
        }

        String namespace = namespacePart.startsWith("[") ? unquoteBracket(namespacePart) : namespacePart;
        if (namespace == null || namespace.isEmpty() || element == null || element.isEmpty()) {
            return null;
        }
        return new MdocClaim(namespace, element);
    }

    /**
     * Keeps only the selected issuer-signed items of an mdoc (base64url or standard base64 CBOR).
     * Kept items stay as their original Tag 24 bytes and issuerAuth is untouched, so the MSO
     * digests and the issuer signature still verify. When nothing is left, the optional
     * {@code nameSpaces} entry is removed, since ISO 18013-5 does not allow an empty map there.
     * Invalid input throws; the full credential is never returned as a fallback.
     *
     * @param mdoc           base64url or standard base64 encoded CBOR mdoc
     * @param selectedClaims claim paths naming the namespace and the element, see {@link #parse(String)}
     * @return the filtered mdoc, in the same base64 variant as the input
     * @throws IllegalArgumentException if the credential or the selection is invalid
     */
    public static String filter(String mdoc, Collection<String> selectedClaims) {
        if (mdoc == null || mdoc.isBlank()) {
            throw new IllegalArgumentException("mso_mdoc credential is empty");
        }
        if (selectedClaims == null) {
            throw new IllegalArgumentException("Selected claims are required to filter an mso_mdoc credential");
        }

        String trimmed = mdoc.trim();
        boolean isStandardBase64 = trimmed.contains("+") || trimmed.contains("/") || trimmed.endsWith("=");
        DataItem root = decodeRoot(decodeBase64(trimmed, isStandardBase64));

        DataItem filteredRoot = filterRoot(root, parseSelectedClaims(selectedClaims));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new CborEncoder(baos).encode(filteredRoot);
        } catch (CborException e) {
            throw new IllegalStateException("Failed to encode filtered mso_mdoc credential", e);
        }
        byte[] filteredBytes = baos.toByteArray();

        if (isStandardBase64) {
            return Base64.getEncoder().encodeToString(filteredBytes);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(filteredBytes);
    }

    /**
     * Reads the docType of an mdoc from its MSO (issuerAuth payload), falling back to a top-level
     * {@code docType} entry.
     *
     * @return the docType, or null if the credential cannot be read
     */
    public static String docType(String mdoc) {
        if (mdoc == null || mdoc.isBlank()) {
            return null;
        }
        try {
            String trimmed = mdoc.trim();
            boolean isStandardBase64 = trimmed.contains("+") || trimmed.contains("/") || trimmed.endsWith("=");
            if (!(decodeRoot(decodeBase64(trimmed, isStandardBase64)) instanceof Map root)) {
                return null;
            }
            Map issuerSigned = getMapValue(root, ISSUER_SIGNED) instanceof Map nested ? nested : root;
            String msoDocType = readMsoDocType(issuerSigned);
            return msoDocType != null ? msoDocType : findStringValue(root, DOC_TYPE);
        } catch (RuntimeException e) {
            log.warn("Failed to read docType of mso_mdoc credential: {}", e.getMessage());
            return null;
        }
    }

    private static String readMsoDocType(Map issuerSigned) {
        if (!(getMapValue(issuerSigned, ISSUER_AUTH) instanceof Array issuerAuth)
                || issuerAuth.getDataItems().size() <= COSE_SIGN1_PAYLOAD_INDEX
                || !(issuerAuth.getDataItems().get(COSE_SIGN1_PAYLOAD_INDEX) instanceof ByteString payload)) {
            return null;
        }
        DataItem msoItem = decodeFirst(payload.getBytes());
        if (msoItem instanceof ByteString wrapped && msoItem.hasTag() && msoItem.getTag().getValue() == ENCODED_CBOR_TAG) {
            msoItem = decodeFirst(wrapped.getBytes());
        }
        return msoItem instanceof Map mso ? findStringValue(mso, DOC_TYPE) : null;
    }

    private static DataItem decodeRoot(byte[] cborBytes) {
        DataItem root = decodeFirst(cborBytes);
        if (root == null) {
            throw new IllegalArgumentException("mso_mdoc credential has no CBOR content");
        }
        return root;
    }

    private static DataItem decodeFirst(byte[] cborBytes) {
        List<DataItem> dataItems;
        try {
            dataItems = newDecoder(cborBytes).decode();
        } catch (CborException e) {
            throw new IllegalArgumentException("mso_mdoc credential is not valid CBOR", e);
        }
        return dataItems == null || dataItems.isEmpty() ? null : dataItems.get(0);
    }

    /**
     * Decoder that keeps every data item as encoded. By default CborDecoder rewrites rational
     * numbers and language-tagged strings, so re-encoding would not reproduce the original bytes.
     */
    private static CborDecoder newDecoder(byte[] cborBytes) {
        CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(cborBytes));
        decoder.setAutoDecodeRationalNumbers(false);
        decoder.setAutoDecodeLanguageTaggedStrings(false);
        return decoder;
    }

    private static byte[] decodeBase64(String value, boolean isStandardBase64) {
        try {
            return isStandardBase64
                    ? Base64.getDecoder().decode(value)
                    : Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            try {
                return Base64.getUrlDecoder().decode(value);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("mso_mdoc credential is not valid base64", ex);
            }
        }
    }

    private static DataItem filterRoot(DataItem root, Set<MdocClaim> claims) {
        if (!(root instanceof Map rootMap)) {
            throw new IllegalArgumentException("mso_mdoc credential root is not a CBOR map");
        }

        DataItem docsItem = getMapValue(rootMap, DOCUMENTS);
        if (docsItem instanceof Array docsArray) {
            Array filteredDocsArray = new Array();
            for (DataItem docItem : docsArray.getDataItems()) {
                if (!(docItem instanceof Map docMap)) {
                    throw new IllegalArgumentException("mso_mdoc document is not a CBOR map");
                }
                filteredDocsArray.add(filterDocument(docMap, claims));
            }
            setMapValue(rootMap, DOCUMENTS, filteredDocsArray);
            return rootMap;
        }

        if (getMapValue(rootMap, ISSUER_SIGNED) instanceof Map) {
            return filterDocument(rootMap, claims);
        }

        if (getMapValue(rootMap, NAME_SPACES) instanceof Map) {
            return filterIssuerSigned(rootMap, claims);
        }

        throw new IllegalArgumentException("mso_mdoc credential has no issuerSigned nameSpaces");
    }

    private static Map filterDocument(Map docMap, Set<MdocClaim> claims) {
        if (!(getMapValue(docMap, ISSUER_SIGNED) instanceof Map issuerSignedMap)) {
            throw new IllegalArgumentException("mso_mdoc document has no issuerSigned map");
        }
        setMapValue(docMap, ISSUER_SIGNED, filterIssuerSigned(issuerSignedMap, claims));
        return docMap;
    }

    private static Map filterIssuerSigned(Map issuerSignedMap, Set<MdocClaim> claims) {
        if (!(getMapValue(issuerSignedMap, NAME_SPACES) instanceof Map nameSpacesMap)) {
            throw new IllegalArgumentException("mso_mdoc issuerSigned has no nameSpaces map");
        }
        Map filteredNameSpaces = filterNameSpaces(nameSpacesMap, claims);
        if (filteredNameSpaces.getKeys().isEmpty()) {
            removeMapValue(issuerSignedMap, NAME_SPACES);
        } else {
            setMapValue(issuerSignedMap, NAME_SPACES, filteredNameSpaces);
        }
        return issuerSignedMap;
    }

    private static Map filterNameSpaces(Map nameSpacesMap, Set<MdocClaim> claims) {
        Map filteredNameSpacesMap = new Map();
        for (DataItem nsKeyItem : nameSpacesMap.getKeys()) {
            if (!(nsKeyItem instanceof UnicodeString nsKey)
                    || !(nameSpacesMap.get(nsKeyItem) instanceof Array itemsArray)) {
                continue;
            }

            Array filteredItemsArray = new Array();
            for (DataItem item : itemsArray.getDataItems()) {
                String elementId = extractElementIdentifier(item);
                if (elementId != null && claims.contains(new MdocClaim(nsKey.getString(), elementId))) {
                    filteredItemsArray.add(item);
                }
            }

            if (!filteredItemsArray.getDataItems().isEmpty()) {
                filteredNameSpacesMap.put(nsKeyItem, filteredItemsArray);
            }
        }
        return filteredNameSpacesMap;
    }

    private static String extractElementIdentifier(DataItem item) {
        if (item instanceof ByteString bs && bs.getBytes() != null && bs.getBytes().length > 0) {
            try {
                if (decodeFirst(bs.getBytes()) instanceof Map innerMap) {
                    return findStringValue(innerMap, ELEMENT_IDENTIFIER);
                }
            } catch (IllegalArgumentException e) {
                log.warn("Failed to decode inner IssuerSignedItem CBOR: {}", e.getMessage());
            }
            return null;
        }
        if (item instanceof Map map) {
            return findStringValue(map, ELEMENT_IDENTIFIER);
        }
        return null;
    }

    private static Set<MdocClaim> parseSelectedClaims(Collection<String> selectedClaims) {
        Set<MdocClaim> claims = new HashSet<>();
        for (String claimPath : selectedClaims) {
            MdocClaim claim = parse(claimPath);
            if (claim == null) {
                log.warn("Ignoring mdoc claim path without a namespace and element: {}", claimPath);
                continue;
            }
            claims.add(claim);
        }
        return claims;
    }

    private static String findStringValue(Map map, String key) {
        return getMapValue(map, key) instanceof UnicodeString value ? value.getString() : null;
    }

    private static DataItem findKey(Map map, String key) {
        for (DataItem k : map.getKeys()) {
            if (k instanceof UnicodeString us && key.equals(us.getString())) {
                return k;
            }
        }
        return null;
    }

    private static DataItem getMapValue(Map map, String key) {
        DataItem k = findKey(map, key);
        return k != null ? map.get(k) : null;
    }

    private static void setMapValue(Map map, String key, DataItem value) {
        DataItem k = findKey(map, key);
        map.put(k != null ? k : new UnicodeString(key), value);
    }

    private static void removeMapValue(Map map, String key) {
        DataItem k = findKey(map, key);
        if (k != null) {
            map.remove(k);
        }
    }

    private static String escape(String segment) {
        return segment.replace("\\", "\\\\").replace("'", "\\'");
    }

    private static int findLastBracketOpen(String path) {
        int closeQuote = path.length() - 2;
        if (closeQuote < 0) {
            return -1;
        }
        char quote = path.charAt(closeQuote);
        if (quote != '\'' && quote != '"') {
            return -1;
        }
        for (int i = closeQuote - 1; i > 0; i--) {
            if (path.charAt(i) == quote && path.charAt(i - 1) == '[' && !isEscaped(path, i)) {
                return i - 1;
            }
        }
        return -1;
    }

    private static boolean isEscaped(String path, int index) {
        int backslashes = 0;
        for (int i = index - 1; i >= 0 && path.charAt(i) == '\\'; i--) {
            backslashes++;
        }
        return backslashes % 2 == 1;
    }

    private static String unquoteBracket(String segment) {
        if (segment.length() < 4 || segment.charAt(0) != '[' || segment.charAt(segment.length() - 1) != ']') {
            return null;
        }
        char quote = segment.charAt(1);
        if ((quote != '\'' && quote != '"') || segment.charAt(segment.length() - 2) != quote) {
            return null;
        }
        String inner = segment.substring(2, segment.length() - 2);
        return inner.replace("\\" + quote, String.valueOf(quote)).replace("\\\\", "\\");
    }
}
