package io.mosip.mimoto.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class UrlParameterUtilsTest {

    private static final String VALID_CLIENT_ID = "https://injiverify.collab.mosip.net";
    private static final String ENCODED_CLIENT_ID = "https%3A%2F%2Finjiverify.collab.mosip.net";
    private static final String VALID_RESPONSE_URI = "https://example.com/callback";
    private static final String ENCODED_RESPONSE_URI = "https%3A%2F%2Fexample.com%2Fcallback";

    @Test
    public void testExtractQueryParameterWithValidClientId() throws Exception {
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertEquals(VALID_CLIENT_ID, result);
    }

    @Test
    public void testExtractQueryParameterWithNoQueryParameters() throws Exception {
        String url = "https://example.com";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithNoParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithMalformedParameter() throws Exception {
        String url = "https://example.com?client_id&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithNullInput() throws Exception {
        String url = null;

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithEmptyValue() throws Exception {
        String url = "https://example.com?client_id=&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertEquals("", result);
    }

    @Test
    public void testExtractQueryParameterWithValidResponseUri() throws Exception {
        String url = "https://example.com?response_uri=" + ENCODED_RESPONSE_URI + "&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertEquals(VALID_RESPONSE_URI, result);
    }

    @Test
    public void testExtractQueryParameterWithNoResponseUriParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithMalformedResponseUri() throws Exception {
        String url = "https://example.com?response_uri&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertNull(result);
    }

    @Test
    public void testExtractQueryParameterWithEmptyResponseUri() throws Exception {
        String url = "https://example.com?response_uri=&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertEquals("", result);
    }

    @Test
    public void testExtractQueryParameterWithCommaValue() throws Exception {
        String url = "https://example.com?response_uri=,";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertEquals(",", result);
    }

    @Test
    public void testExtractQueryParameterWithMultipleCommas() throws Exception {
        String url = "https://example.com?response_uri=uri1,uri2,uri3";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertEquals("uri1,uri2,uri3", result);
    }

    @Test
    public void testExtractQueryParameterWithSpecialCharacters() throws Exception {
        String specialClientId = "client-id_with.special+chars";
        String encodedClientId = "client-id_with.special%2Bchars";
        String url = "https://example.com?client_id=" + encodedClientId + "&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertEquals(specialClientId, result);
    }

    @Test
    public void testExtractQueryParameterWithSpecialCharactersInUri() throws Exception {
        String specialUri = "https://example.com/callback?param=value&other=test";
        String encodedUri = "https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue%26other%3Dtest";
        String url = "https://example.com?response_uri=" + encodedUri + "&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "response_uri");

        assertEquals(specialUri, result);
    }

    @Test
    public void testExtractQueryParameterWithWhitespace() throws Exception {
        String url = "https://example.com?client_id=%20&other_param=value";

        String result = UrlParameterUtils.extractQueryParameter(url, "client_id");

        assertEquals(" ", result);
    }

    @Test
    public void testExtractQueryParameterWithAnyParameterName() throws Exception {
        String url = "https://example.com?custom_param=value123&other_param=value2";

        String result = UrlParameterUtils.extractQueryParameter(url, "custom_param");

        assertEquals("value123", result);
    }

    @Test
    public void testExtractQueryParameterWithMultipleParameters() throws Exception {
        String url = "https://example.com?param1=value1&param2=value2&param3=value3";

        String result1 = UrlParameterUtils.extractQueryParameter(url, "param1");
        String result2 = UrlParameterUtils.extractQueryParameter(url, "param2");
        String result3 = UrlParameterUtils.extractQueryParameter(url, "param3");

        assertEquals("value1", result1);
        assertEquals("value2", result2);
        assertEquals("value3", result3);
    }

}
