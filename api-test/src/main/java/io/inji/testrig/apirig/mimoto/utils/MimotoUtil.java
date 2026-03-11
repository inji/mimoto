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
import io.mosip.testrig.apirig.utils.RestClient;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;
import io.restassured.response.Response;

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
							otp = OTPListener.getOtp(emailId);
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
		return "did:web:injiverify." + env_name + ".mosip.net:v1:verify";
	}

	private static String getAuthorizationRequestUrlMock() {
		String env_name = extractEnvironmentName();
		return "openid4vp://authorize?client_id=" + getClientIdForInjiVerify()
			+ "&request_uri=" + "https://injiverify." + env_name + ".mosip.net/v1/verify/vp-request/";
	}
}