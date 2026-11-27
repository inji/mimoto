package io.inji.testrig.apirig.mimoto.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
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
	
	public static List<String> getEnabledPlugins() {
		return PluginUtil.parsePlugins(getOptionalProperty("runPlugin"));
	}

	public static boolean isPluginEnabled(String plugin) {
		return plugin != null && getEnabledPlugins().contains(plugin.toLowerCase(Locale.ROOT));
	}

	// Validates every enabled plugin at startup and returns the eSignet URL of the default plugin
	public static String getEsignetBaseUrl() {
		List<String> plugins = getEnabledPlugins();
		boolean anyPattern = false;
		for (String plugin : plugins) {
			getEsignetBaseUrlForPlugin(plugin);
			anyPattern |= getDefinedProperty(plugin + PluginUtil.TESTCASE_PATTERN_SUFFIX) != null;
		}
		if (plugins.size() > 1 && !anyPattern) {
			LOGGER.warn("runPlugin enables " + plugins + " but no '<plugin>" + PluginUtil.TESTCASE_PATTERN_SUFFIX
					+ "' is defined, so every test case will use '" + plugins.get(0) + "'");
		}
		return getEsignetBaseUrl(null);
	}

	public static String getEsignetBaseUrl(String testCaseName) {
		String plugin = PluginUtil.resolvePlugin(testCaseName, getEnabledPlugins(),
				MimotoConfigManager::getDefinedProperty);
		String esignetBaseUrl = plugin == null ? null : getEsignetBaseUrlForPlugin(plugin);
		LOGGER.info("Plugin for test case '" + testCaseName + "' is '" + plugin + "' (enabled plugins: "
				+ getEnabledPlugins() + "), eSignet base url: " + esignetBaseUrl);
		if (esignetBaseUrl != null) {
			propertiesMap.put("eSignetbaseurl", esignetBaseUrl);
		}
		return esignetBaseUrl;
	}

	private static String getEsignetBaseUrlForPlugin(String plugin) {
		String hostKey = getOptionalProperty(plugin + "-identity-esignet-host");
		if (hostKey == null || hostKey.isBlank()) {
			LOGGER.error("No '" + plugin + "-identity-esignet-host' property configured for runPlugin '" + plugin + "'");
			return null;
		}
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", hostKey);
	}

	private static String getOptionalProperty(String key) {
		try {
			return getproperty(key);
		} catch (RuntimeException e) {
			LOGGER.debug("Optional property '" + key + "' could not be read: " + e.getMessage());
			return null;
		}
	}

	// Returns the value only when the key is really defined. Missing values are
	// reported as null so optional plugin settings are never treated as configured.
	private static String getDefinedProperty(String key) {
		Object loaded = propertiesMap.get(key);
		String value = loaded != null ? loaded.toString() : getOptionalProperty(key);
		if (value == null || value.isBlank() || "null".equalsIgnoreCase(value.trim()) || value.trim().equals(key)) {
			return null;
		}
		return value;
	}
	
	public static String getEsignetSunBirdBaseURL() {
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", getproperty("sunbirdrc-insurance-esignet-host"));
	}

	public static String getInjiVerifyBaseURL() {
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.injiverify.host");
	}

}
