package io.inji.testrig.apirig.mimoto.testscripts;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import io.inji.testrig.apirig.mimoto.utils.MimotoConfigManager;
import io.inji.testrig.apirig.mimoto.utils.MimotoUtil;
import io.mosip.testrig.apirig.dto.OutputValidationDto;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.ReportUtil;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.response.Response;
import org.json.JSONObject;
import org.json.JSONArray;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;

public class PostWithPathParamsHeadersAndCookieForAutoGenId extends MimotoUtil implements ITest {
	private static final Logger logger = Logger.getLogger(PostWithPathParamsHeadersAndCookieForAutoGenId.class);
	protected String testCaseName = "";
	public String pathParams = null;
	public String headers = null;
	public String idKeyName = null;

	private static final Set<String> SEEN_REQUEST_URIS = ConcurrentHashMap.newKeySet();
	private static final Set<String> SEEN_STATES = ConcurrentHashMap.newKeySet();
	private static final Set<String> PAR_CAPTURED_TESTCASES = ConcurrentHashMap.newKeySet();

	public static boolean isParCaptured(String authorizeTestCaseName) {
		return PAR_CAPTURED_TESTCASES.contains(authorizeTestCaseName);
	}

	@BeforeClass
	public static void setLogLevel() {
		if (MimotoConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}

	/**
	 * get current testcaseName
	 */
	@Override
	public String getTestName() {
		return testCaseName;
	}

	/**
	 * Data provider class provides test case list
	 * 
	 * @return object of data provider
	 */
	@DataProvider(name = "testcaselist")
	public Object[] getTestCaseList(ITestContext context) {
		String ymlFile = context.getCurrentXmlTest().getLocalParameters().get("ymlFile");
		pathParams = context.getCurrentXmlTest().getLocalParameters().get("pathParams");
		idKeyName = context.getCurrentXmlTest().getLocalParameters().get("idKeyName");
		headers = context.getCurrentXmlTest().getLocalParameters().get("headers");
		logger.info("Started executing yml: " + ymlFile);
		return getYmlTestData(ymlFile);
	}

	/**
	 * Test method for OTP Generation execution
	 * 
	 * @param objTestParameters
	 * @param testScenario
	 * @param testcaseName
	 * @throws AuthenticationTestException
	 * @throws AdminTestException
	 */
	@Test(dataProvider = "testcaselist")
	public void test(TestCaseDTO testCaseDTO) throws AuthenticationTestException, AdminTestException, SecurityXSSException {
		testCaseName = testCaseDTO.getTestCaseName();
		testCaseDTO = MimotoUtil.isTestCaseValidForTheExecution(testCaseDTO);
		
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(
					GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}

	
		String inputJson = getJsonFromTemplate(testCaseDTO.getInput(), testCaseDTO.getInputTemplate());
		inputJson = MimotoUtil.inputstringKeyWordHandeler(inputJson, testCaseName);

		// Inject the double-submit XSRF cookie/header pair so the api-internal gateway CSRF check
		// passes without leaking those fields into the yml/hbs. Only applied for the guest DPoP
		// flow (role=userDefinedCookie) to avoid polluting request bodies of other tests that use
		// this script class with a real MOSIP auth role.
		if ("userDefinedCookie".equals(testCaseDTO.getRole())) {
			inputJson = injectRealXsrfToken(inputJson);
		}

		if (inputJson.contains("authorizationRequestUrl")) {

			try {

				JSONObject json = new JSONObject(inputJson);
				if (json.has("authorizationRequestUrl")) {
					String authUrl = json.getString("authorizationRequestUrl");

					authUrl = authUrl.replace("&amp;", "&").replace("%25", "%").replace("\\u0026", "&")
							.replace("\\u003d", "=");
					json.put("authorizationRequestUrl", authUrl);
					inputJson = json.toString();
				}
			} catch (Exception e) {
				logger.warn("Warning: Unable to normalize authorizationRequestUrl");
			}
		}

		Response response;
		// The closed-source commons method attaches only ONE cookie via the userDefinedCookie role.
		// For flows that must forward a real session cookie (e.g. Google login SESSION) AND the
		// XSRF-TOKEN cookie for the gateway's double-submit CSRF check, route to a manual
		// RestAssured call that sends both cookies.
		if (needsDualCookiePath(testCaseDTO.getRole(), inputJson)) {
			response = manualPostWithSessionAndXsrf(testCaseDTO.getEndPoint(), inputJson,
					testCaseDTO.getTestCaseName(), pathParams, headers, idKeyName);
		} else {
			response = postWithPathParamsBodyHeadersAndCookieForAutoGeneratedId(
					ApplnURI + testCaseDTO.getEndPoint(), inputJson, COOKIENAME, testCaseDTO.getRole(),
					testCaseDTO.getTestCaseName(), pathParams, idKeyName, headers);
		}

		validateParAuthorizationResponse(testCaseDTO, response, inputJson);

		// Unlike SimplePostForAutoGenId, the closed-source commons call site here never scans
		// Set-Cookie for a SESSION= value, so `sessionCookie` idKeyName must be captured manually
		// via the same public writeAutoGeneratedId(...) the framework uses.
		if (idKeyName != null && idKeyName.contains("sessionCookie")) {
			captureSessionCookie(response, testCaseDTO.getTestCaseName());
		}

		Map<String, List<OutputValidationDto>> ouputValid = OutputValidationUtil.doJsonOutputValidation(
				response.asString(), getJsonFromTemplate(testCaseDTO.getOutput(), testCaseDTO.getOutputTemplate()),
				testCaseDTO, response.getStatusCode());
		Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));

		if (!OutputValidationUtil.publishOutputResult(ouputValid))
			throw new AdminTestException("Failed at output validation");

	}

	/**
	 * Validates the PAR form of a successful IssuersAuthorize response. The
	 * authorization URL must carry only the OAuth parameters that are required
	 * after a successful PAR exchange.
	 */
	private void validateParAuthorizationResponse(TestCaseDTO testCaseDTO, Response response, String inputJson)
			throws AdminTestException {
		if (testCaseDTO.getEndPoint() == null
				|| !testCaseDTO.getEndPoint().contains("/issuers/")
				|| !testCaseDTO.getEndPoint().contains("/authorize")
				|| response == null
				|| response.getStatusCode() < 200
				|| response.getStatusCode() >= 300) {
			return;
		}

		try {
			String issuerId = new JSONObject(inputJson).optString("issuerId", "");
			if (issuerId.isBlank()) {
				throw new AdminTestException("IssuersAuthorize request does not contain issuerId");
			}
			JSONObject authorizationServerMetadata = fetchAuthorizationServerMetadata(issuerId);
			String parEndpoint = authorizationServerMetadata.optString(
					"pushed_authorization_request_endpoint", "");
			boolean parRequired = authorizationServerMetadata.optBoolean(
					"require_pushed_authorization_requests", false);

			if (!parEndpoint.isBlank() && !parEndpoint.regionMatches(true, 0, "https://", 0, 8)) {
				throw new AdminTestException("AS metadata advertises a non-HTTPS PAR endpoint: " + parEndpoint);
			}
			if (parRequired && parEndpoint.isBlank()) {
				throw new AdminTestException(
						"AS metadata requires PAR but does not advertise pushed_authorization_request_endpoint");
			}

			JSONObject body;
			try {
				body = new JSONObject(response.asString());
			} catch (Exception exception) {
				throw new AdminTestException("IssuersAuthorize returned a non-JSON response: " + exception.getMessage());
			}

			Set<String> expectedFields = Set.of("authorizationUrl", "state");
			Set<String> actualFields = body.keySet();
			if (!actualFields.equals(expectedFields)) {
				throw new AdminTestException("IssuersAuthorize response must contain only " + expectedFields
						+ ", but received " + actualFields);
			}

			Object stateValue = body.opt("state");
			if (!(stateValue instanceof String) || ((String) stateValue).isBlank()) {
				throw new AdminTestException("IssuersAuthorize response state must be a non-empty JSON string");
			}

			String authorizationUrl = body.optString("authorizationUrl", "");
			if (authorizationUrl.isBlank()) {
				throw new AdminTestException("IssuersAuthorize response contains an empty authorizationUrl");
			}

			URI uri = URI.create(authorizationUrl);
			if (!uri.isAbsolute()
					|| (!"https".equalsIgnoreCase(uri.getScheme())
							&& !"http".equalsIgnoreCase(uri.getScheme()))
					|| uri.getHost() == null
					|| uri.getRawFragment() != null) {
				throw new AdminTestException(
						"PAR authorizationUrl must be an absolute HTTP(S) URL without a fragment");
			}
			if (uri.getRawQuery() == null || uri.getRawQuery().isBlank()) {
				throw new AdminTestException("PAR authorizationUrl does not contain query parameters");
			}

			Map<String, String> queryParameters = new HashMap<>();
			for (String parameter : uri.getRawQuery().split("&")) {
				String[] nameAndValue = parameter.split("=", 2);
				String name = URLDecoder.decode(nameAndValue[0], StandardCharsets.UTF_8);
				String value = nameAndValue.length == 2
						? URLDecoder.decode(nameAndValue[1], StandardCharsets.UTF_8) : "";
				if (queryParameters.containsKey(name)) {
					throw new AdminTestException(
							"PAR authorizationUrl contains a duplicate query parameter");
				}
				queryParameters.put(name, value);
			}

			if (!parEndpoint.isBlank()) {
				Set<String> expectedParameters = Set.of("client_id", "request_uri");
				if (!queryParameters.keySet().equals(expectedParameters)) {
					throw new AdminTestException("PAR authorizationUrl must contain only " + expectedParameters
							+ ", but received " + queryParameters.keySet());
				}
				for (String parameter : expectedParameters) {
					if (queryParameters.get(parameter).isBlank()) {
						throw new AdminTestException("PAR authorizationUrl contains an empty " + parameter);
					}
				}

				if (!SEEN_REQUEST_URIS.add(queryParameters.get("request_uri"))) {
					throw new AdminTestException(
							"PAR request_uri was reused across authorize calls; each attempt must push a new PAR request");
				}

				writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "requestUri", queryParameters.get("request_uri"));
				writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "parClientId", queryParameters.get("client_id"));
				PAR_CAPTURED_TESTCASES.add(testCaseDTO.getTestCaseName());
			} else {
				Set<String> requiredDirectParameters = Set.of("client_id", "redirect_uri", "response_type",
						"scope", "state", "code_challenge", "code_challenge_method");
				if (queryParameters.containsKey("request_uri")) {
					throw new AdminTestException(
							"Direct authorization URL must not contain request_uri when PAR is not advertised");
				}
				if (!queryParameters.keySet().containsAll(requiredDirectParameters)) {
					throw new AdminTestException("Direct authorization URL is missing one or more required parameters: "
							+ requiredDirectParameters + "; received " + queryParameters.keySet());
				}
				for (String parameter : requiredDirectParameters) {
					if (queryParameters.get(parameter).isBlank()) {
						throw new AdminTestException("Direct authorization URL contains an empty " + parameter);
					}
				}
			}

			if (!SEEN_STATES.add((String) stateValue)) {
				throw new AdminTestException(
						"IssuersAuthorize state was reused across authorize calls; each attempt must use a fresh state");
			}
		} catch (IllegalArgumentException exception) {
			throw new AdminTestException("IssuersAuthorize returned an invalid authorizationUrl: "
					+ exception.getMessage());
		}
	}

	/**
	 * Reads the AS metadata through Mimoto's issuer well-known proxy to discover the
	 * authorization-server host, then reads the standard OAuth AS metadata document.
	 * This is deliberately observational: api-test does not alter AS metadata.
	 */
	private JSONObject fetchAuthorizationServerMetadata(String issuerId) throws AdminTestException {
		try {
			Response issuerWellKnown = RestAssured.given()
					.relaxedHTTPSValidation()
					.accept(ContentType.JSON)
					.get(ApplnURI + "/v1/mimoto/issuers/" + issuerId + "/well-known-proxy");
			if (issuerWellKnown.getStatusCode() < 200 || issuerWellKnown.getStatusCode() >= 300) {
				throw new AdminTestException("Unable to read issuer well-known proxy; HTTP status "
						+ issuerWellKnown.getStatusCode());
			}

			JSONObject issuerMetadata = new JSONObject(issuerWellKnown.asString());
			JSONArray authorizationServers = issuerMetadata.optJSONArray("authorization_servers");
			if (authorizationServers == null || authorizationServers.length() == 0) {
				throw new AdminTestException("Issuer well-known proxy does not contain authorization_servers");
			}
			String authorizationServer = authorizationServers.optString(0, "");
			if (authorizationServer.isBlank()) {
				throw new AdminTestException("Issuer well-known proxy contains an empty authorization server");
			}

			// Try the OAuth AS metadata document first, then fall back to OIDC discovery for
			// servers (e.g. some eSignet versions) that only publish openid-configuration.
			URI issuerUri = URI.create(authorizationServer);
			String issuerPath = issuerUri.getRawPath() == null ? "" : issuerUri.getRawPath();
			if (issuerPath.endsWith("/")) {
				issuerPath = issuerPath.substring(0, issuerPath.length() - 1);
			}
			String origin = issuerUri.getScheme() + "://" + issuerUri.getRawAuthority();
			String[] metadataUrls = { origin + "/.well-known/oauth-authorization-server" + issuerPath,
					origin + issuerPath + "/.well-known/openid-configuration" };
			StringBuilder failures = new StringBuilder();
			for (String metadataUrl : metadataUrls) {
				Response authorizationMetadata = RestAssured.given()
						.relaxedHTTPSValidation()
						.accept(ContentType.JSON)
						.get(metadataUrl);
				if (authorizationMetadata.getStatusCode() >= 200 && authorizationMetadata.getStatusCode() < 300) {
					return new JSONObject(authorizationMetadata.asString());
				}
				failures.append(" HTTP ").append(authorizationMetadata.getStatusCode()).append(" from ")
						.append(metadataUrl).append(';');
			}
			throw new AdminTestException("Unable to read authorization-server metadata;" + failures);
		} catch (AdminTestException exception) {
			throw exception;
		} catch (Exception exception) {
			throw new AdminTestException("Unable to read authorization-server metadata: " + exception.getMessage());
		}
	}

	/**
	 * The method ser current test name to result
	 * 
	 * @param result
	 */
	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
	}

}
