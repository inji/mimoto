package io.mosip.mimoto.util;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import io.mosip.mimoto.util.MdocSelectiveDisclosureUtil.MdocClaim;
import org.junit.Test;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import static io.mosip.mimoto.util.MdocTestData.ISO_NAMESPACE;
import static io.mosip.mimoto.util.MdocTestData.MDL_DOC_TYPE;
import static io.mosip.mimoto.util.MdocTestData.document;
import static io.mosip.mimoto.util.MdocTestData.encode;
import static io.mosip.mimoto.util.MdocTestData.fromBase64Url;
import static io.mosip.mimoto.util.MdocTestData.isoItems;
import static io.mosip.mimoto.util.MdocTestData.issuerSigned;
import static io.mosip.mimoto.util.MdocTestData.item;
import static io.mosip.mimoto.util.MdocTestData.toBase64Url;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class MdocSelectiveDisclosureUtilTest {

    private static final MdocClaim ISO_FAMILY_NAME = new MdocClaim(ISO_NAMESPACE, "family_name");

    @Test
    public void toJsonPathKeepsDottedNamespaceInOneSegment() {
        assertEquals("$['org.iso.18013.5.1']['family_name']",
                MdocSelectiveDisclosureUtil.toJsonPath(ISO_NAMESPACE, "family_name"));
    }

    @Test
    public void toJsonPathRoundTripsThroughParse() {
        String path = MdocSelectiveDisclosureUtil.toJsonPath("org.example.1", "it's.dotted");
        assertEquals(new MdocClaim("org.example.1", "it's.dotted"), MdocSelectiveDisclosureUtil.parse(path));
    }

    @Test
    public void parseSupportsAllClaimPathForms() {
        assertEquals(ISO_FAMILY_NAME, MdocSelectiveDisclosureUtil.parse("org.iso.18013.5.1.family_name"));
        assertEquals(ISO_FAMILY_NAME, MdocSelectiveDisclosureUtil.parse("$['org.iso.18013.5.1']['family_name']"));
        assertEquals(ISO_FAMILY_NAME, MdocSelectiveDisclosureUtil.parse("$['org.iso.18013.5.1'].family_name"));
        assertEquals(ISO_FAMILY_NAME, MdocSelectiveDisclosureUtil.parse(
                DcqlClaimSetHelper.buildClaimPath(List.of(ISO_NAMESPACE, "family_name"))));
        assertEquals(ISO_FAMILY_NAME, MdocSelectiveDisclosureUtil.parse(
                DcqlClaimSetHelper.buildJsonPath(List.of(ISO_NAMESPACE, "family_name"))));
    }

    @Test
    public void parseReturnsNullWithoutNamespace() {
        assertNull(MdocSelectiveDisclosureUtil.parse("family_name"));
        assertNull(MdocSelectiveDisclosureUtil.parse("$.family_name"));
        assertNull(MdocSelectiveDisclosureUtil.parse(" "));
        assertNull(MdocSelectiveDisclosureUtil.parse(null));
    }

    @Test
    public void filterKeepsOnlySelectedItemWithOriginalBytes() throws Exception {
        byte[] givenName = item(0, "given_name", "Alice");
        byte[] familyName = item(1, "family_name", "Smith");
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, isoItems(givenName, familyName)));

        String filtered = MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.given_name"));

        Array items = isoItemsOf(filtered);
        assertEquals(1, items.getDataItems().size());
        ByteString kept = (ByteString) items.getDataItems().get(0);
        assertEquals(24, kept.getTag().getValue());
        assertArrayEquals(givenName, kept.getBytes());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(givenName),
                MessageDigest.getInstance("SHA-256").digest(kept.getBytes()));
    }

    @Test
    public void filterKeepsIssuerAuthUnchanged() throws Exception {
        Map document = document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice")));
        byte[] issuerAuth = encode(((Map) document.get(new UnicodeString("issuerSigned"))).get(new UnicodeString("issuerAuth")));

        String filtered = MdocSelectiveDisclosureUtil.filter(toBase64Url(document), List.of());

        assertArrayEquals(issuerAuth, encode(issuerSignedOf(filtered).get(new UnicodeString("issuerAuth"))));
    }

    @Test
    public void filterSupportsIssuerSignedRoot() throws Exception {
        byte[] familyName = item(1, "family_name", "Smith");
        String mdoc = toBase64Url(issuerSigned(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"), familyName)));

        String filtered = MdocSelectiveDisclosureUtil.filter(mdoc, List.of("$['org.iso.18013.5.1']['family_name']"));

        Map nameSpaces = (Map) ((Map) fromBase64Url(filtered)).get(new UnicodeString("nameSpaces"));
        Array items = (Array) nameSpaces.get(new UnicodeString(ISO_NAMESPACE));
        assertEquals(1, items.getDataItems().size());
        assertArrayEquals(familyName, ((ByteString) items.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterSupportsDeviceResponseRoot() throws Exception {
        byte[] givenName = item(0, "given_name", "Alice");
        Array documents = new Array();
        documents.add(document(MDL_DOC_TYPE, isoItems(givenName, item(1, "family_name", "Smith"))));
        Map deviceResponse = new Map();
        deviceResponse.put(new UnicodeString("version"), new UnicodeString("1.0"));
        deviceResponse.put(new UnicodeString("documents"), documents);

        String filtered = MdocSelectiveDisclosureUtil.filter(toBase64Url(deviceResponse), List.of("org.iso.18013.5.1.given_name"));

        Map document = (Map) ((Array) ((Map) fromBase64Url(filtered)).get(new UnicodeString("documents"))).getDataItems().get(0);
        Map nameSpaces = (Map) ((Map) document.get(new UnicodeString("issuerSigned"))).get(new UnicodeString("nameSpaces"));
        Array items = (Array) nameSpaces.get(new UnicodeString(ISO_NAMESPACE));
        assertEquals(1, items.getDataItems().size());
        assertArrayEquals(givenName, ((ByteString) items.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterWithDcqlClaimPathSharesOnlyThatClaim() throws Exception {
        byte[] familyName = item(1, "family_name", "Smith");
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"), familyName)));
        String claimPath = DcqlClaimSetHelper.buildClaimPath(List.of(ISO_NAMESPACE, "family_name"));

        Array items = isoItemsOf(MdocSelectiveDisclosureUtil.filter(mdoc, List.of(claimPath)));

        assertEquals(1, items.getDataItems().size());
        assertArrayEquals(familyName, ((ByteString) items.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterDoesNotDiscloseSameElementFromAnotherNamespace() throws Exception {
        byte[] isoGivenName = item(0, "given_name", "Alice");
        java.util.Map<String, List<byte[]>> itemsByNamespace = new LinkedHashMap<>();
        itemsByNamespace.put(ISO_NAMESPACE, List.of(isoGivenName));
        itemsByNamespace.put("org.example.photoid.1", List.of(item(1, "given_name", "Alicia")));
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, itemsByNamespace));

        Map nameSpaces = nameSpacesOf(MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.given_name")));

        assertEquals(1, nameSpaces.getKeys().size());
        Array items = (Array) nameSpaces.get(new UnicodeString(ISO_NAMESPACE));
        assertArrayEquals(isoGivenName, ((ByteString) items.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterDoesNotConfuseDottedNamespaceAndDottedElement() throws Exception {
        // ("org.example.1", "contact.phone") and ("org.example.1.contact", "phone") are different claims
        byte[] dottedElement = item(0, "contact.phone", "111");
        byte[] dottedNamespace = item(1, "phone", "222");
        java.util.Map<String, List<byte[]>> itemsByNamespace = new LinkedHashMap<>();
        itemsByNamespace.put("org.example.1", List.of(dottedElement));
        itemsByNamespace.put("org.example.1.contact", List.of(dottedNamespace));
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, itemsByNamespace));

        Map byNamespacePath = nameSpacesOf(MdocSelectiveDisclosureUtil.filter(mdoc,
                List.of(DcqlClaimSetHelper.buildClaimPath(List.of("org.example.1.contact", "phone")))));
        assertEquals(1, byNamespacePath.getKeys().size());
        Array items = (Array) byNamespacePath.get(new UnicodeString("org.example.1.contact"));
        assertArrayEquals(dottedNamespace, ((ByteString) items.getDataItems().get(0)).getBytes());

        Map byElementPath = nameSpacesOf(MdocSelectiveDisclosureUtil.filter(mdoc,
                List.of(DcqlClaimSetHelper.buildClaimPath(List.of("org.example.1", "contact.phone")))));
        assertEquals(1, byElementPath.getKeys().size());
        Array otherItems = (Array) byElementPath.get(new UnicodeString("org.example.1"));
        assertArrayEquals(dottedElement, ((ByteString) otherItems.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterRemovesNameSpacesWhenNothingIsSelected() throws Exception {
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"))));

        Map issuerSigned = issuerSignedOf(MdocSelectiveDisclosureUtil.filter(mdoc, Collections.emptyList()));

        assertNull(issuerSigned.get(new UnicodeString("nameSpaces")));
        assertNotNull(issuerSigned.get(new UnicodeString("issuerAuth")));
    }

    @Test
    public void filterRemovesNameSpacesWhenNothingMatches() throws Exception {
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"))));

        assertNull(issuerSignedOf(MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.Given_Name")))
                .get(new UnicodeString("nameSpaces")));
        assertNull(issuerSignedOf(MdocSelectiveDisclosureUtil.filter(mdoc, List.of("given_name")))
                .get(new UnicodeString("nameSpaces")));
    }

    @Test
    public void filterKeepsTag30AndTag38ItemsAsEncoded() throws Exception {
        // With the decoder defaults these would be rewritten, or rejected when they are not
        // a two-item array, so the mdoc could not be re-encoded byte for byte
        Array rational = new Array();
        rational.add(new UnsignedInteger(1));
        rational.add(new UnsignedInteger(3));
        rational.setTag(30);
        Array rationalWithThreeItems = new Array();
        rationalWithThreeItems.add(new UnsignedInteger(1));
        rationalWithThreeItems.add(new UnsignedInteger(3));
        rationalWithThreeItems.add(new UnsignedInteger(5));
        rationalWithThreeItems.setTag(30);
        Array languageTagged = new Array();
        languageTagged.add(new UnicodeString("en"));
        languageTagged.add(new UnicodeString("Alice"));
        languageTagged.setTag(38);
        UnicodeString languageTaggedText = new UnicodeString("Alice");
        languageTaggedText.setTag(38);

        Map document = document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice")));
        document.put(new UnicodeString("rational"), rational);
        document.put(new UnicodeString("rationalWithThreeItems"), rationalWithThreeItems);
        document.put(new UnicodeString("languageTagged"), languageTagged);
        document.put(new UnicodeString("languageTaggedText"), languageTaggedText);
        byte[] original = encode(document);
        String mdoc = Base64.getUrlEncoder().withoutPadding().encodeToString(original);

        String filtered = MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.given_name"));

        assertArrayEquals(original, Base64.getUrlDecoder().decode(filtered));
    }

    @Test
    public void filterKeepsTag30AndTag38InsideSelectedItemValue() throws Exception {
        Array rationalWithThreeItems = new Array();
        rationalWithThreeItems.add(new UnsignedInteger(1));
        rationalWithThreeItems.add(new UnsignedInteger(3));
        rationalWithThreeItems.add(new UnsignedInteger(5));
        rationalWithThreeItems.setTag(30);
        byte[] ratio = item(0, "ratio", rationalWithThreeItems);
        String mdoc = toBase64Url(document(MDL_DOC_TYPE, isoItems(ratio, item(1, "family_name", "Smith"))));

        Array items = isoItemsOf(MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.ratio")));

        assertEquals(1, items.getDataItems().size());
        assertArrayEquals(ratio, ((ByteString) items.getDataItems().get(0)).getBytes());
    }

    @Test
    public void filterKeepsStandardBase64Variant() throws Exception {
        byte[] original = encode(document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"))));
        String mdoc = Base64.getEncoder().encodeToString(original);

        String filtered = MdocSelectiveDisclosureUtil.filter(mdoc, List.of("org.iso.18013.5.1.given_name"));

        assertArrayEquals(original, Base64.getDecoder().decode(filtered));
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterThrowsWhenSelectedClaimsNull() throws Exception {
        MdocSelectiveDisclosureUtil.filter(toBase64Url(document(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice")))), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterThrowsWhenCredentialIsNotBase64() {
        MdocSelectiveDisclosureUtil.filter("not base64 !!", List.of("org.iso.18013.5.1.given_name"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterThrowsWhenCredentialIsNotCborMdoc() {
        String notAnMdoc = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x01});
        MdocSelectiveDisclosureUtil.filter(notAnMdoc, List.of("org.iso.18013.5.1.given_name"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterThrowsWhenCredentialIsBlank() {
        MdocSelectiveDisclosureUtil.filter(" ", List.of("org.iso.18013.5.1.given_name"));
    }

    @Test
    public void docTypeIsReadFromMsoOfIssuerSigned() throws Exception {
        String mdoc = toBase64Url(issuerSigned(MDL_DOC_TYPE, isoItems(item(0, "given_name", "Alice"))));

        assertEquals(MDL_DOC_TYPE, MdocSelectiveDisclosureUtil.docType(mdoc));
    }

    @Test
    public void docTypeIsReadFromMsoOfDocument() throws Exception {
        String mdoc = toBase64Url(document("org.example.photoid.1", isoItems(item(0, "given_name", "Alice"))));

        assertEquals("org.example.photoid.1", MdocSelectiveDisclosureUtil.docType(mdoc));
    }

    @Test
    public void docTypeFallsBackToTopLevelDocType() throws Exception {
        Map document = new Map();
        document.put(new UnicodeString("docType"), new UnicodeString(MDL_DOC_TYPE));
        document.put(new UnicodeString("issuerSigned"), new Map());

        assertEquals(MDL_DOC_TYPE, MdocSelectiveDisclosureUtil.docType(toBase64Url(document)));
    }

    @Test
    public void docTypeIsNullForUnreadableCredential() {
        assertNull(MdocSelectiveDisclosureUtil.docType(null));
        assertNull(MdocSelectiveDisclosureUtil.docType(" "));
        assertNull(MdocSelectiveDisclosureUtil.docType("not base64 !!"));
        assertNull(MdocSelectiveDisclosureUtil.docType(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x01})));
    }

    private static Map issuerSignedOf(String mdoc) throws Exception {
        return (Map) ((Map) fromBase64Url(mdoc)).get(new UnicodeString("issuerSigned"));
    }

    private static Map nameSpacesOf(String mdoc) throws Exception {
        return (Map) issuerSignedOf(mdoc).get(new UnicodeString("nameSpaces"));
    }

    private static Array isoItemsOf(String mdoc) throws Exception {
        Map nameSpaces = nameSpacesOf(mdoc);
        assertNotNull(nameSpaces);
        return (Array) nameSpaces.get(new UnicodeString(ISO_NAMESPACE));
    }
}
