package io.inji.testrig.apirig.mimoto.utils;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.testng.SkipException;

import com.github.javafaker.Faker;

import io.inji.testrig.apirig.mimoto.testrunner.InjiTestRunner;
import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.ConfigManager;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.NotificationListener;
import io.mosip.testrig.apirig.utils.RestClient;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class MimotoUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(MimotoUtil.class);
	private static String otpEnabled = "true";
	private static Faker faker = new Faker();
	private static String fullNameForSunBirdR = generateFullNameForSunBirdR();
	private static String dobForSunBirdR = generateDobForSunBirdR();
	private static String policyNumberForSunBirdR = generateRandomNumberString(9);

	public static List<String> testCasesInRunScope = new ArrayList<>();

	public static void setLogLevel() {
		if (MimotoConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}

	public static String isOTPEnabled() {
		String value = getValueFromMimotoActuator("/mimoto-default.properties", "mosip.otp.download.enable").isBlank()
				? System.getenv("isOTPEnabled")
				: getValueFromMimotoActuator("/mimoto-default.properties", "mosip.otp.download.enable");
		if (value != null && !(value.isBlank()))
			otpEnabled = value;
		logger.info("OTP Enabled value: " + otpEnabled);
		return otpEnabled;
	}

	public static TestCaseDTO changeContextURLByFlag(TestCaseDTO testCaseDTO) {
		if (!(System.getenv("useOldContextURL") == null) && !(System.getenv("useOldContextURL").isBlank())
				&& System.getenv("useOldContextURL").equalsIgnoreCase("true")) {
			if (testCaseDTO.getEndPoint().contains("/v1/mimoto/")) {
				testCaseDTO.setEndPoint(testCaseDTO.getEndPoint().replace("/v1/mimoto/", "/residentmobileapp/"));
			}
			if (testCaseDTO.getInput().contains("/v1/mimoto/")) {
				testCaseDTO.setInput(testCaseDTO.getInput().replace("/v1/mimoto/", "/residentmobileapp/"));
			}
		}

		return testCaseDTO;
	}

	public static boolean isValidJSONObject(String input) {
		try {
			new JSONObject(input);
			return true;
		} catch (JSONException e) {
			return false;
		}
	}

	public static TestCaseDTO isTestCaseValidForTheExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		currentTestCaseName = testCaseName;

		int indexof = testCaseName.indexOf("_");
		String modifiedTestCaseName = testCaseName.substring(indexof + 1);

		addTestCaseDetailsToMap(modifiedTestCaseName, testCaseDTO.getUniqueIdentifier());
		
		if (!testCasesInRunScope.isEmpty()
				&& testCasesInRunScope.contains(testCaseDTO.getUniqueIdentifier()) == false) {
			throw new SkipException(GlobalConstants.NOT_IN_RUN_SCOPE_MESSAGE);
		}

		// Handle extra workflow dependencies
		if (testCaseDTO != null && testCaseDTO.getAdditionalDependencies() != null
				&& AdminTestUtil.generateDependency == true) {
			addAdditionalDependencies(testCaseDTO);
		}

		String endpoint = testCaseDTO.getEndPoint();
		String inputJson = testCaseDTO.getInput();

		// When the captcha is enabled we cannot execute the test case as we can not generate the captcha token
		if (isCaptchaEnabled() == true) {
			GlobalMethods.reportCaptchaStatus(GlobalConstants.CAPTCHA_ENABLED, true);
			throw new SkipException(GlobalConstants.CAPTCHA_ENABLED_MESSAGE);
		}

		if (InjiTestRunner.skipAll == true) {
			throw new SkipException(GlobalConstants.PRE_REQUISITE_FAILED_MESSAGE);
		}

		if (isOTPEnabled().equals("false")) {
			if (testCaseDTO.getEndPoint().contains(GlobalConstants.SEND_OTP_ENDPOINT)
					|| testCaseDTO.getInput().contains(GlobalConstants.SEND_OTP_ENDPOINT)
					|| testCaseName.startsWith(GlobalConstants.MIMOTO_CREDENTIAL_STATUS)
					|| (testCaseName.startsWith("Mimoto_Generate_") && endpoint.contains("/v1/mimoto/vid"))) {
				throw new SkipException(GlobalConstants.OTP_FEATURE_NOT_SUPPORTED);
			}

			if (inputJson.contains("_vid$")) {
				inputJson = inputJson.replace("_vid$", "_VID$");
				testCaseDTO.setInput(inputJson);
			}
		}
		if (isOTPEnabled().equals("true") && endpoint.contains("/idrepository/v1/vid")) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}
		return testCaseDTO;
	}

	public static void dbCleanUp() {
		DBManager.executeDBQueries(MimotoConfigManager.getKMDbUrl(), MimotoConfigManager.getKMDbUser(),
				MimotoConfigManager.getKMDbPass(), MimotoConfigManager.getKMDbSchema(),
				getGlobalResourcePath() + "/" + "config/keyManagerCertDataDeleteQueries.txt");
		DBManager.executeDBQueries(MimotoConfigManager.getIdaDbUrl(), MimotoConfigManager.getIdaDbUser(),
				MimotoConfigManager.getPMSDbPass(), MimotoConfigManager.getIdaDbSchema(),
				getGlobalResourcePath() + "/" + "config/idaCertDataDeleteQueries.txt");
		DBManager.executeDBQueries(MimotoConfigManager.getMASTERDbUrl(), MimotoConfigManager.getMasterDbUser(),
				MimotoConfigManager.getMasterDbPass(), MimotoConfigManager.getMasterDbSchema(),
				getGlobalResourcePath() + "/" + "config/masterDataCertDataDeleteQueries.txt");
	}

	public static String getOTPFromSMTP(String inputJson, TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		JSONObject request = new JSONObject(inputJson);
		String emailId = null;
		String otp = null;

		if (testCaseName.contains("ESignet_AuthenticateUser") && request.has(GlobalConstants.REQUEST)) {
			if (request.getJSONObject(GlobalConstants.REQUEST).has(GlobalConstants.CHALLENGELIST)) {
				if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
						.length() > 0) {
					if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
							.getJSONObject(0).has(GlobalConstants.CHALLENGE)) {
						if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
								.getJSONObject(0).getString(GlobalConstants.CHALLENGE)
								.endsWith(GlobalConstants.MAILINATOR_COM)
								|| request.getJSONObject(GlobalConstants.REQUEST)
										.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
										.getString(GlobalConstants.CHALLENGE).endsWith(GlobalConstants.MOSIP_NET)
								|| request.getJSONObject(GlobalConstants.REQUEST)
										.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
										.getString(GlobalConstants.CHALLENGE).endsWith(GlobalConstants.OTP_AS_PHONE)) {
							emailId = request.getJSONObject(GlobalConstants.REQUEST)
									.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
									.getString(GlobalConstants.CHALLENGE);
							if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE)) {
								emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
								emailId = removeLeadingPlusSigns(emailId);
							}
							logger.info(emailId);
							otp = NotificationListener.getOtp(emailId);
							request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
									.getJSONObject(0).put(GlobalConstants.CHALLENGE, otp);
							inputJson = request.toString();
							return inputJson;
						}
					}
				}
			}
		}

		return inputJson;
	}

	public static String inputstringKeyWordHandeler(String jsonString, String testCaseName) {
		if (jsonString.contains("$ID:")) {
			jsonString = replaceIdWithAutogeneratedId(jsonString, "$ID:");
		}

		if (jsonString.contains("\"codeChallenge\"") && jsonString.contains("code_challenge=")) {
			jsonString = extractCodeChallengeFromAuthorizationUrl(jsonString);
		}

		if (jsonString.contains(GlobalConstants.TIMESTAMP)) {
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
		}

		if (jsonString.contains("$UNIQUENONCEVALUEFORESIGNET$")) {
			jsonString = replaceKeywordValue(jsonString, "$UNIQUENONCEVALUEFORESIGNET$",
					String.valueOf(Calendar.getInstance().getTimeInMillis()));
		}

		if (jsonString.contains("$SUNBIRDINSURANCEAUTHFACTORTYPE$")) {
			String authFactorType = MimotoConfigManager
					.getproperty(MimotoConstants.SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE_STRING);

			String valueToReplace = (authFactorType != null && !authFactorType.isBlank()) ? authFactorType
					: MimotoConstants.SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE;

			jsonString = replaceKeywordValue(jsonString, "$SUNBIRDINSURANCEAUTHFACTORTYPE$", valueToReplace);

		}

		if (jsonString.contains("$GOOGLE_IDT_TOKEN$")) {
			jsonString = replaceKeywordValue(jsonString, "$GOOGLE_IDT_TOKEN$", getGoogleIdToken());
		}

		if (jsonString.contains("$POLICYNUMBERFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$POLICYNUMBERFORSUNBIRDRC$", policyNumberForSunBirdR);
		}

		if (jsonString.contains("$FULLNAMEFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$FULLNAMEFORSUNBIRDRC$", fullNameForSunBirdR);
		}

		if (jsonString.contains("$DOBFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$DOBFORSUNBIRDRC$", dobForSunBirdR);
		}

		if (jsonString.contains("$CHALLENGEVALUEFORSUNBIRDC$")) {

			HashMap<String, String> mapForChallenge = new HashMap<String, String>();
			mapForChallenge.put(GlobalConstants.FULLNAME, fullNameForSunBirdR);
			mapForChallenge.put(GlobalConstants.DOB, dobForSunBirdR);

			String challenge = gson.toJson(mapForChallenge);

			String challengeValue = BiometricDataProvider.toBase64Url(challenge);

			jsonString = replaceKeywordValue(jsonString, "$CHALLENGEVALUEFORSUNBIRDC$", challengeValue);
		}
		
		if (jsonString.contains("$PUBLICKEYFORBINDING$")) {
			jsonString = replaceKeywordValue(jsonString, "$PUBLICKEYFORBINDING$",
					generatePublicKeyForMimoto());
		}
		
		if (jsonString.contains("$INJIREDIRECTURI$")) {
			jsonString = replaceKeywordValue(jsonString, "$INJIREDIRECTURI$",
					ApplnURI.replace(GlobalConstants.API_INTERNAL, "injiweb") + "/redirect");
		}
		if (jsonString.contains("$AUTHORIZATION_REQUEST_URL$")) {
			jsonString = replaceKeywordValue(jsonString, "$AUTHORIZATION_REQUEST_URL$",
					getAuthorizationRequestUrlMock());

		}
		if (jsonString.contains("$CLIENT_ID_INJI_VERIFY$")) {
			jsonString = replaceKeywordValue(jsonString, "$CLIENT_ID_INJI_VERIFY$", getClientIdForInjiVerify());
		}
		if (jsonString.contains("$GETCLIENTIDFORMOSIPIDFROMMIMOTOACTUATOR$")) {
			String clientIdSection = MimotoConfigManager.getproperty("mimoto-oidc-mosipid-partner-clientid");
			jsonString = replaceKeywordWithValue(jsonString, "$GETCLIENTIDFORMOSIPIDFROMMIMOTOACTUATOR$",
					getValueFromMimotoActuator("overrides", clientIdSection));
		} else if (jsonString.contains("$GETCLIENTIDFORINSURANCEFROMMIMOTOACTUATOR$")) {
			String clientIdSection = MimotoConfigManager.getproperty("mimoto-oidc-sunbird-partner-clientid");
			jsonString = replaceKeywordWithValue(jsonString, "$GETCLIENTIDFORINSURANCEFROMMIMOTOACTUATOR$",
					getValueFromMimotoActuator("overrides", clientIdSection));
		}

		return jsonString;

	}

	private static final java.util.regex.Pattern CODE_CHALLENGE_FIELD_PATTERN = java.util.regex.Pattern
			.compile("(\"codeChallenge\"\\s*:\\s*\")([^\"]*)(\")");

	/**
	 * Mimoto's DPoP authorize response only exposes the code_challenge embedded in
	 * authorizationUrl's query string (not as its own JSON field), so when the yml's
	 * codeChallenge input is chained from that authorizationUrl via $ID:, this pulls
	 * just the code_challenge param out of it here on the test side.
	 */
	public static String extractCodeChallengeFromAuthorizationUrl(String jsonString) {
		java.util.regex.Matcher matcher = CODE_CHALLENGE_FIELD_PATTERN.matcher(jsonString);
		if (!matcher.find()) {
			return jsonString;
		}
		String url = matcher.group(2).replace("&amp;", "&").replace("\\u0026", "&").replace("\\u003d", "=");
		int queryStart = url.indexOf('?');
		if (queryStart < 0) {
			return jsonString;
		}
		String codeChallenge = null;
		for (String param : url.substring(queryStart + 1).split("&")) {
			int eq = param.indexOf('=');
			if (eq > 0 && param.substring(0, eq).equals("code_challenge")) {
				codeChallenge = java.net.URLDecoder.decode(param.substring(eq + 1),
						java.nio.charset.StandardCharsets.UTF_8);
				break;
			}
		}
		if (codeChallenge == null) {
			return jsonString;
		}
		return matcher.replaceFirst("$1" + java.util.regex.Matcher.quoteReplacement(codeChallenge) + "$3");
	}

	public static String replaceKeywordValue(String jsonString, String keyword, String value) {
		if (value != null && !value.isEmpty())
			return jsonString.replace(keyword, value);
		else {
			if (keyword.contains("$ID:"))
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword
						+ " please check the results of testcase: " + getTestCaseIDFromKeyword(keyword));
			else
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword);

		}
	}

	public static String generatePublicKeyForMimoto() {

		String vcString = "";
		try {
			KeyPairGenerator keyPairGenerator = getKeyPairGeneratorInstance();
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				pemWriter.writeObject(publicKey);
				pemWriter.flush();
				vcString = stringWriter.toString();
				if (System.getProperty("os.name").toLowerCase().contains("windows")) {
					vcString = vcString.replaceAll("\r\n", "\\\\n");
				} else {
					vcString = vcString.replaceAll("\n", "\\\\n");
				}
			} catch (Exception e) {
				throw e;
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return vcString;
	}

	public static String generateFullNameForSunBirdR() {
		return faker.name().fullName();
	}

	public static String generateDobForSunBirdR() {
		Faker faker = new Faker();
		LocalDate dob = faker.date().birthday().toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDate();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		return dob.format(formatter);
	}

	public static JSONArray mimotoActuatorResponseArray = null;

	public static String getValueFromMimotoActuator(String section, String key) {
		String url = ApplnURI + ConfigManager.getproperty("actuatorMimotoEndpoint");
		if (!(System.getenv("useOldContextURL") == null) && !(System.getenv("useOldContextURL").isBlank())
				&& System.getenv("useOldContextURL").equalsIgnoreCase("true")) {
			if (url.contains("/v1/mimoto/")) {
				url = url.replace("/v1/mimoto/", "/residentmobileapp/");
			}
		}
		String actuatorCacheKey = url + section + key;
		String value = actuatorValueCache.get(actuatorCacheKey);
		if (value != null && !value.isEmpty())
			return value;

		try {
			if (mimotoActuatorResponseArray == null) {
				Response response = null;
				JSONObject responseJson = null;
				response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);

				responseJson = new JSONObject(response.getBody().asString());
				mimotoActuatorResponseArray = responseJson.getJSONArray("propertySources");
			}
			for (int i = 0, size = mimotoActuatorResponseArray.length(); i < size; i++) {
				JSONObject eachJson = mimotoActuatorResponseArray.getJSONObject(i);
				if (eachJson.get("name").toString().contains(section)) {
					value = eachJson.getJSONObject(GlobalConstants.PROPERTIES).getJSONObject(key)
							.get(GlobalConstants.VALUE).toString();
					if (ConfigManager.IsDebugEnabled())
						logger.info("Actuator: " + url + " key: " + key + " value: " + value);
					break;
				}
			}
			actuatorValueCache.put(actuatorCacheKey, value);

			return value;
		} catch (Exception e) {
			logger.error(GlobalConstants.EXCEPTION_STRING_2 + e);
			logger.error("Unable to fetch the value from the actuator. URL = " + url + " section = " + section + " key "
					+ key);
			return "";
		}

	}

	private static String getGoogleIdToken() {
		String idToken = null;

		Map<String, String> requestMap = new HashMap<>();
		requestMap.put("clientId", MimotoConfigManager.getproperty("google.client.id"));
		requestMap.put("clientSecret", MimotoConfigManager.getproperty("google.client.secret"));
		requestMap.put("refreshToken", MimotoConfigManager.getproperty("google.refresh.token"));
		requestMap.put("grant_type", "refresh_token");
		String url = props.getProperty("googleIdToken");

		Response response = RestClient.postRequestWithFormDataBody(url, requestMap);

		if (response.getStatusCode() != 200) {
			String errorResponse = response.getBody().toString();
			throw new RuntimeException("Failed to get ID token. HTTP status code: " + response.getStatusCode()
					+ ", response body: " + errorResponse);
		}

		JSONObject jsonObject = new JSONObject(response.getBody().asString());

		if (jsonObject != null) {
			idToken = jsonObject.get("id_token").toString();
		}

		if (idToken == null || idToken.isEmpty()) {
			throw new RuntimeException("id_token not found in response: " + response);
		}

		logger.info("Obtained id_token: " + idToken); // Debug log
		return idToken;

	}

	private static String extractEnvironmentName() {
		final String startMarker = "api-internal.";
		final String endMarker = ".mosip.net";
		
		int startIndex = ApplnURI.indexOf(startMarker);
		int endIndex = ApplnURI.indexOf(endMarker);
		
		if (startIndex == -1 || endIndex == -1 || startIndex >= endIndex) {
			throw new IllegalArgumentException(
				"Failed to extract environment name from ApplnURI: " + ApplnURI
			);
		}
		
		startIndex += startMarker.length();
		return ApplnURI.substring(startIndex, endIndex);
	}

	private static String getClientIdForInjiVerify() {
		String env_name = extractEnvironmentName();
		return "decentralized_identifier:did:web:injiverify." + env_name + ".mosip.net:v1:verify";
	}

	private static String getAuthorizationRequestUrlMock() {
		String env_name = extractEnvironmentName();
		return "openid4vp://authorize?client_id=" + getClientIdForInjiVerify()
			+ "&request_uri=" + "https://injiverify." + env_name + ".mosip.net/v1/verify/v2/vp-request/";
	}

	/**
	 * Pulls the "cookie"/"cookieName" fields out of the request JSON (they're transport
	 * concerns, not real body fields) so callers can attach them as an actual RestAssured cookie.
	 */
	private record NamedCookie(String name, String value) {
	}

	private NamedCookie extractAndRemoveCookie(JSONObject json) {
		String cookieValue = json.optString("cookie", "");
		String cookieName = json.optString("cookieName", "");
		json.remove("cookie");
		json.remove("cookieName");
		return new NamedCookie(cookieName, cookieValue);
	}

	/**
	 * Posts the credential download request as form data, additionally forwarding a
	 * DPoP "state" header and a guest DPoP session cookie when present in the input
	 * JSON (both are removed from the form body since the backend expects them as
	 * a header/cookie, not form fields).
	 */
	protected byte[] postWithFormDataBodyForPdfWithStateHeaderAndCookie(String url, String inputJson) {
		JSONObject json = new JSONObject(inputJson);
		String state = json.optString("state", "");
		json.remove("state");
		NamedCookie cookie = extractAndRemoveCookie(json);

		Map<String, String> formParams = new HashMap<>();
		Iterator<String> keys = json.keys();
		while (keys.hasNext()) {
			String key = keys.next();
			formParams.put(key, String.valueOf(json.get(key)));
		}

		RequestSpecification request = RestAssured.given().relaxedHTTPSValidation().contentType(ContentType.URLENC)
				.formParams(formParams)
				.header(XSRF_HEADERNAME, CSRF_TOKEN)
				.cookie(GlobalConstants.XSRF_TOKEN, CSRF_COOKIE);
		if (!state.isBlank()) {
			request = request.header("state", state);
		}
		if (!cookie.value().isBlank() && !cookie.name().isBlank()) {
			request = request.cookie(cookie.name(), cookie.value());
		}
		Response response = request.post(url);
		return response.asByteArray();
	}

	/**
	 * Injects the XSRF header field (extracted by the closed-source `headers` loop) and the
	 * userDefinedCookie fields (used by the closed-source role handling to set the XSRF cookie)
	 * into the request JSON, using a real server-fetched XSRF-TOKEN. Keeps the yml/hbs clean of
	 * gateway-CSRF plumbing.
	 */
	protected String injectRealXsrfToken(String inputJson) {
		String xsrfValue = fetchRealXsrfToken(null, null);
		if (xsrfValue == null || xsrfValue.isBlank()) {
			throw new RuntimeException("Unable to fetch a real XSRF-TOKEN to inject into the request");
		}
		try {
			JSONObject json = new JSONObject(inputJson);
			if (!json.has(XSRF_HEADERNAME)) {
				json.put(XSRF_HEADERNAME, xsrfValue);
			}
			if (!json.has("cookie")) {
				json.put("cookie", xsrfValue);
			}
			if (!json.has("cookieName")) {
				json.put("cookieName", GlobalConstants.XSRF_TOKEN);
			}
			return json.toString();
		} catch (JSONException e) {
			logger.warn("Warning: Unable to inject XSRF bypass fields into input JSON");
			return inputJson;
		}
	}

	/**
	 * Dual-cookie path is needed when the yml is forwarding a real session cookie (not the
	 * XSRF-TOKEN bypass) — the request must carry both that session cookie AND the XSRF-TOKEN
	 * cookie/header to pass the gateway CSRF check.
	 */
	protected boolean needsDualCookiePath(String role, String inputJson) {
		if (!"userDefinedCookie".equals(role)) {
			return false;
		}
		try {
			JSONObject json = new JSONObject(inputJson);
			return json.has("cookie") && json.has("cookieName")
					&& !GlobalConstants.XSRF_TOKEN.equals(json.optString("cookieName"));
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Primes a real Spring Security CSRF cookie via a lightweight public GET — Config.java's
	 * CsrfTokenCookieFilter issues a fresh XSRF-TOKEN cookie on every GET, even unauthenticated
	 * ones. Attaches the caller's session cookie when provided (Google login flow) so the
	 * priming call runs in the same session context as the real request. Returns null on any
	 * failure so callers can fall back to the dummy double-submit value.
	 */
	protected String fetchRealXsrfToken(String sessionCookieName, String sessionCookieValue) {
		try {
			RequestSpecification request = RestAssured.given().relaxedHTTPSValidation();
			if (sessionCookieName != null && sessionCookieValue != null
					&& !sessionCookieName.isBlank() && !sessionCookieValue.isBlank()) {
				request = request.cookie(sessionCookieName, sessionCookieValue);
			}
			Response response = request.get(ApplnURI + "/v1/mimoto/issuers");
			return response.getCookie(GlobalConstants.XSRF_TOKEN);
		} catch (Exception e) {
			logger.warn("Warning: Unable to fetch a real XSRF-TOKEN, falling back to a dummy value");
			return null;
		}
	}

	/**
	 * Builds and sends the POST directly via RestAssured, attaching both the caller-supplied
	 * session cookie (Google login SESSION) and a real XSRF-TOKEN cookie/header. Also captures
	 * idKeyName body-field values via the same public writeAutoGeneratedId(...) the framework
	 * uses.
	 */
	protected Response manualPostWithSessionAndXsrf(String endPoint, String inputJson, String currentTestCaseName,
			String pathParams, String headers, String idKeyName) {
		JSONObject json = new JSONObject(inputJson);
		NamedCookie cookie = extractAndRemoveCookie(json);
		json.remove(XSRF_HEADERNAME);

		Map<String, String> pathParamsMap = new HashMap<>();
		if (pathParams != null) {
			for (String p : pathParams.split(",")) {
				String key = p.trim();
				if (!key.isEmpty() && json.has(key)) {
					pathParamsMap.put(key, String.valueOf(json.get(key)));
					json.remove(key);
				}
			}
		}

		Map<String, String> headersMap = new HashMap<>();
		if (headers != null) {
			for (String h : headers.split(",")) {
				String key = h.trim();
				if (key.isEmpty() || XSRF_HEADERNAME.equals(key)) {
					continue;
				}
				if (json.has(key)) {
					headersMap.put(key, String.valueOf(json.get(key)));
					json.remove(key);
				}
			}
		}
		// Prime a real server-issued XSRF-TOKEN using the same session cookie; fail fast if it can't be fetched
		String xsrfValue = fetchRealXsrfToken(cookie.name(), cookie.value());
		if (xsrfValue == null || xsrfValue.isBlank()) {
			throw new RuntimeException("Unable to fetch a real XSRF-TOKEN to inject into the request");
		}
		headersMap.put(XSRF_HEADERNAME, xsrfValue);

		String bodyStr = json.toString();
		String url = ApplnURI + endPoint;
		GlobalMethods.reportRequest(headersMap.toString(), bodyStr, url);

		RequestSpecification request = RestAssured.given().relaxedHTTPSValidation()
				.contentType(ContentType.JSON)
				.accept(ContentType.JSON)
				.headers(headersMap)
				.cookie(GlobalConstants.XSRF_TOKEN, xsrfValue)
				.body(bodyStr);
		if (!pathParamsMap.isEmpty()) {
			request = request.pathParams(pathParamsMap);
		}
		if (!cookie.value().isBlank() && !cookie.name().isBlank()) {
			request = request.cookie(cookie.name(), cookie.value());
		}
		Response response = request.post(url);
		GlobalMethods.reportResponse(response.getHeaders().asList().toString(), url, response);

		// Mirror the closed-source auto-gen capture: only write when the test case name has _sid
		if (idKeyName != null && currentTestCaseName != null
				&& currentTestCaseName.toLowerCase().contains("_sid")) {
			JSONObject respBody = new JSONObject(response.asString());
			for (String key : idKeyName.split(",")) {
				String field = key.trim();
				if ("sessionCookie".equals(field) || field.isEmpty()) {
					continue;
				}
				if (respBody.has(field)) {
					writeAutoGeneratedId(currentTestCaseName, field, String.valueOf(respBody.get(field)));
				} else if ("id".equals(field) && respBody.has("verifier")
						&& respBody.getJSONObject("verifier").has("id")) {
					writeAutoGeneratedId(currentTestCaseName, field,
							respBody.getJSONObject("verifier").getString("id"));
				}
			}
		}
		return response;
	}

	/**
	 * Manually replicates the closed-source SESSION= cookie capture that
	 * postRequestWithCookieAuthHeaderAndXsrfTokenForAutoGenId performs internally (used by
	 * GoogleLoginToken) — this script's own commons call site never scans Set-Cookie headers,
	 * so downstream `$ID:<sid>_sessionCookie$` references would otherwise resolve empty.
	 * Stores only the value after "SESSION=" to match the closed-source cache format exactly.
	 */
	protected void captureSessionCookie(Response response, String currentTestCaseName) {
		for (String setCookieHeader : response.getHeaders().getValues("Set-Cookie")) {
			for (String cookiePart : setCookieHeader.split(";")) {
				String trimmed = cookiePart.trim();
				if (trimmed.startsWith("SESSION=")) {
					writeAutoGeneratedId(currentTestCaseName, "sessionCookie", trimmed.substring("SESSION=".length()));
					return;
				}
			}
		}
		logger.warn("Warning: No SESSION cookie found in response to capture as sessionCookie");
	}
}