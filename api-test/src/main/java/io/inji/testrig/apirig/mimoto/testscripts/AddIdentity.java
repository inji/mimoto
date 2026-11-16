package io.inji.testrig.apirig.mimoto.testscripts;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import io.inji.testrig.apirig.mimoto.utils.MimotoConfigManager;
import io.inji.testrig.apirig.mimoto.utils.MimotoUtil;
import io.mosip.testrig.apirig.dto.OutputValidationDto;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.testrunner.JsonPrecondtion;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.KernelAuthentication;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.ReportUtil;
import io.mosip.testrig.apirig.utils.RestClient;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.response.Response;

public class AddIdentity extends MimotoUtil implements ITest {
	private static final Logger logger = Logger.getLogger(AddIdentity.class);
	protected String testCaseName = "";
	public Response response = null;

	/**
	 * get current testcaseName
	 */
	@Override
	public String getTestName() {
		return testCaseName;

	}

	@BeforeClass
	public static void setLogLevel() {
		if (MimotoConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}

	/**
	 * Data provider class provides test case list
	 * 
	 * @return object of data provider
	 */
	@DataProvider(name = "testcaselist")
	public Object[] getTestCaseList(ITestContext context) {
		String ymlFile = context.getCurrentXmlTest().getLocalParameters().get("ymlFile");
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
		boolean isMockMdlIdentity = testCaseName.contains("AddIdentity_MockMdl");
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(
					GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}
		if (!isMockMdlIdentity) {
			testCaseDTO.setInputTemplate(AdminTestUtil.modifySchemaGenerateHbs(testCaseDTO.isRegenerateHbs()));
		}
		String uin = "";
		if (!isMockMdlIdentity) {
			uin = JsonPrecondtion
					.getValueFromJson(
							RestClient.getRequestWithCookie(ApplnURI + "/v1/idgenerator/uin",
									MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON, COOKIENAME,
									new KernelAuthentication().getTokenByRole(testCaseDTO.getRole())).asString(),
							"response.uin");
		}

		testCaseDTO = MimotoUtil.isTestCaseValidForTheExecution(testCaseDTO);
		testCaseDTO = MimotoUtil.changeContextURLByFlag(testCaseDTO);

		DateFormat dateFormatter = new SimpleDateFormat("yyyyMMddHHmmss");
		Calendar cal = Calendar.getInstance();
		String timestampValue = dateFormatter.format(cal.getTime());
		String genRid = "27847" + generateRandomNumberString(10) + timestampValue;
		// TODO: Use the dynamically generated MockMdl individual ID when the issuer
		// data provider plugin changes.
		String mockMdlIndividualId = isMockMdlIdentity ? String.valueOf(System.currentTimeMillis()) : "";

		String jsonInput = testCaseDTO.getInput();

		String inputJson = isMockMdlIdentity
				? getJsonFromTemplate(jsonInput, testCaseDTO.getInputTemplate())
				: getJsonFromTemplate(jsonInput, testCaseDTO.getInputTemplate(), false);

		inputJson = inputJson.replace("$UIN$", uin);
		inputJson = inputJson.replace("$RID$", genRid);
		inputJson = inputJson.replace("$MOCKMDLINDIVIDUALID$", mockMdlIndividualId);
		String phoneNumber = isMockMdlIdentity ? "9" + generateRandomNumberString(9) : "";
		String email = testCaseName + "_" + BaseTestCase.runContext +"@mosip.net";
		if (inputJson.contains("$PHONENUMBERFORIDENTITY$")) {
			if (!isMockMdlIdentity && !phoneSchemaRegex.isEmpty())
				try {
					phoneNumber = genStringAsperRegex(phoneSchemaRegex);
				} catch (Exception e) {
					logger.error(e.getMessage());
				}
			inputJson = replaceKeywordWithValue(inputJson, "$PHONENUMBERFORIDENTITY$", phoneNumber);
			inputJson = replaceKeywordWithValue(inputJson, "$EMAILVALUE$", email);
		}
		inputJson = MimotoUtil.inputstringKeyWordHandeler(inputJson, testCaseName);

		try {
			JSONObject requestJson = new JSONObject(inputJson);
			JSONObject identityRequest = requestJson.optJSONObject("request");
			JSONObject identity = identityRequest != null ? identityRequest.optJSONObject("identity") : null;
			Object emailField = identity != null ? identity.opt("email")
					: identityRequest != null ? identityRequest.opt("email") : null;
			String requestEmail = "";
			if (emailField instanceof String) {
				requestEmail = (String) emailField;
			} else if (emailField instanceof JSONArray) {
				JSONObject entry = ((JSONArray) emailField).optJSONObject(0);
				if (entry != null) {
					requestEmail = entry.optString("value", "");
				}
			}
			if (!requestEmail.isBlank()) {
				email = requestEmail;
			}
		} catch (Exception e) {
			logger.warn("Could not extract email from AddIdentity request JSON, falling back to computed value: "
					+ e.getMessage());
		}

		String baseUrl = isMockMdlIdentity ? MimotoConfigManager.getMockIdentitySystemBaseURL() : ApplnURI;
		if (isMockMdlIdentity && (baseUrl == null || baseUrl.isBlank())) {
			throw new AdminTestException("Mock identity system base URL is not configured");
		}
		response = postWithBodyAndCookie(baseUrl + testCaseDTO.getEndPoint(), inputJson, COOKIENAME,
				testCaseDTO.getRole(), testCaseDTO.getTestCaseName());

		Map<String, List<OutputValidationDto>> ouputValid = OutputValidationUtil.doJsonOutputValidation(
				response.asString(), getJsonFromTemplate(testCaseDTO.getOutput(), testCaseDTO.getOutputTemplate()),
				testCaseDTO, response.getStatusCode());
		Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));

		if (!OutputValidationUtil.publishOutputResult(ouputValid))
			throw new AdminTestException("Failed at output validation");
		if (testCaseDTO.getTestCaseName().contains("_Pos")) {
			if (isMockMdlIdentity) {
				writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "INDIVIDUALID", mockMdlIndividualId);
			} else {
				writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "UIN", uin);
				writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "RID", genRid);
			}
			writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "EMAIL", email);
			writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "PHONE", phoneNumber);
		}
		if (!phoneNumber.isEmpty())
			writeAutoGeneratedId(testCaseDTO.getTestCaseName(), "PHONE", phoneNumber);
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

	@AfterClass(alwaysRun = true)
	public void waittime() {

		try {
			logger.info(
					"waiting for " + properties.getProperty("Delaytime") + " mili secs after UIN Generation In IDREPO");
			Thread.sleep(Long.parseLong(properties.getProperty("Delaytime")));

		} catch (Exception e) {
			logger.error("Exception : " + e.getMessage());
			Thread.currentThread().interrupt();
		}

	}
}
