package io.mosip.mimoto.util;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Builds small mso_mdoc credentials for tests: IssuerSigned with Tag 24 items and an issuerAuth
 * COSE_Sign1 whose payload is the Tag 24 wrapped MSO carrying the docType.
 */
public final class MdocTestData {

    public static final String ISO_NAMESPACE = "org.iso.18013.5.1";
    public static final String MDL_DOC_TYPE = "org.iso.18013.5.1.mDL";

    private MdocTestData() {
    }

    public static byte[] item(int digestId, String elementId, DataItem value) throws Exception {
        Map item = new Map();
        item.put(new UnicodeString("digestID"), new UnsignedInteger(digestId));
        item.put(new UnicodeString("random"), new ByteString(new byte[]{1, 2, 3, 4}));
        item.put(new UnicodeString("elementIdentifier"), new UnicodeString(elementId));
        item.put(new UnicodeString("elementValue"), value);
        return encode(item);
    }

    public static byte[] item(int digestId, String elementId, String value) throws Exception {
        return item(digestId, elementId, new UnicodeString(value));
    }

    /** IssuerSigned: {@code { nameSpaces, issuerAuth }}, as an issuer returns it. */
    public static Map issuerSigned(String docType, java.util.Map<String, List<byte[]>> itemsByNamespace) throws Exception {
        Map nameSpaces = new Map();
        for (java.util.Map.Entry<String, List<byte[]>> entry : itemsByNamespace.entrySet()) {
            Array items = new Array();
            for (byte[] itemBytes : entry.getValue()) {
                ByteString tagged = new ByteString(itemBytes);
                tagged.setTag(24);
                items.add(tagged);
            }
            nameSpaces.put(new UnicodeString(entry.getKey()), items);
        }

        Map issuerSigned = new Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), nameSpaces);
        issuerSigned.put(new UnicodeString("issuerAuth"), issuerAuth(docType));
        return issuerSigned;
    }

    /** Document: {@code { docType, issuerSigned }}. */
    public static Map document(String docType, java.util.Map<String, List<byte[]>> itemsByNamespace) throws Exception {
        Map document = new Map();
        document.put(new UnicodeString("docType"), new UnicodeString(docType));
        document.put(new UnicodeString("issuerSigned"), issuerSigned(docType, itemsByNamespace));
        return document;
    }

    public static java.util.Map<String, List<byte[]>> isoItems(byte[]... items) {
        java.util.Map<String, List<byte[]>> itemsByNamespace = new LinkedHashMap<>();
        itemsByNamespace.put(ISO_NAMESPACE, List.of(items));
        return itemsByNamespace;
    }

    public static String toBase64Url(DataItem root) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(root));
    }

    public static DataItem fromBase64Url(String mdoc) throws Exception {
        CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(Base64.getUrlDecoder().decode(mdoc)));
        decoder.setAutoDecodeRationalNumbers(false);
        decoder.setAutoDecodeLanguageTaggedStrings(false);
        return decoder.decode().get(0);
    }

    public static byte[] encode(DataItem item) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(item);
        return baos.toByteArray();
    }

    private static Array issuerAuth(String docType) throws Exception {
        Map mso = new Map();
        mso.put(new UnicodeString("version"), new UnicodeString("1.0"));
        mso.put(new UnicodeString("digestAlgorithm"), new UnicodeString("SHA-256"));
        mso.put(new UnicodeString("docType"), new UnicodeString(docType));

        ByteString taggedMso = new ByteString(encode(mso));
        taggedMso.setTag(24);

        Array coseSign1 = new Array();
        coseSign1.add(new ByteString(new byte[]{(byte) 0xA1, 0x01, 0x26}));
        coseSign1.add(new Map());
        coseSign1.add(new ByteString(encode(taggedMso)));
        coseSign1.add(new ByteString(new byte[]{9, 9, 9}));
        return coseSign1;
    }
}
