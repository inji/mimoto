package io.inji.testrig.apirig.mimoto.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import io.inji.testrig.apirig.mimoto.testrunner.InjiTestRunner;
import io.mosip.testrig.apirig.utils.ConfigManager;

public class MimotoConfigManager extends ConfigManager{
	private static final Logger LOGGER = Logger.getLogger(MimotoConfigManager.class);
	
	public static void init() {
		Logger configManagerLogger = Logger.getLogger(ConfigManager.class);
		configManagerLogger.setLevel(Level.WARN);
		
		Map<String, Object> moduleSpecificPropertiesMap = new HashMap<>();
		// Load scope specific properties
		try {
			String path = InjiTestRunner.getGlobalResourcePath() + "/config/mimoto.properties";
			Properties props = getproperties(path);
			// Convert Properties to Map and add to moduleSpecificPropertiesMap
			for (String key : props.stringPropertyNames()) {
				moduleSpecificPropertiesMap.put(key, props.getProperty(key));
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
		// Add module specific properties as well.
		init(moduleSpecificPropertiesMap);
	}
	
	public static String getSunbirdBaseURL() {
		return MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.sunbird.url");
	}

	public static int getMaxFailedAttemptsAllowedPerCycle() {
		return Integer.parseInt(MimotoUtil.getValueFromMimotoActuator("https://github.com/inji/inji-config/mimoto-default.properties", "wallet.passcode.maxFailedAttemptsAllowedPerCycle"));
	}
	
	public static String getEsignetBaseUrl() {
		String esignetBaseUrl = null;
		if (getproperty("runPlugin").equals("mosipid")) {
			esignetBaseUrl = "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", getproperty("mosipid-identity-esignet-host"));
		} else if (getproperty("runPlugin").equals("mockid")) {
			esignetBaseUrl = "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", getproperty("mock-identity-esignet-host"));
		}
		if(esignetBaseUrl != null) {
			propertiesMap.put("eSignetbaseurl", esignetBaseUrl);
		}
		return esignetBaseUrl;
	}
	
	public static String getEsignetSunBirdBaseURL() {
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", getproperty("sunbirdrc-insurance-esignet-host"));
	}
	
	public static String getInjiVerifyBaseURL() {
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.injiverify.host");
	}

}
