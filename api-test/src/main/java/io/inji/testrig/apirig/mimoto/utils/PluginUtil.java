package io.inji.testrig.apirig.mimoto.utils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

public final class PluginUtil {

	public static final String TESTCASE_PATTERN_SUFFIX = "-testcase-pattern";

	private static final String PLUGIN_SEPARATORS = "[,;\\s]+";

	private PluginUtil() {
	}

	public static List<String> parsePlugins(String runPlugin) {
		Set<String> plugins = new LinkedHashSet<>();
		if (runPlugin != null) {
			for (String plugin : runPlugin.trim().split(PLUGIN_SEPARATORS)) {
				if (!plugin.isEmpty()) {
					plugins.add(plugin.toLowerCase(Locale.ROOT));
				}
			}
		}
		return new ArrayList<>(plugins);
	}

	public static String resolvePlugin(String testCaseName, List<String> enabledPlugins,
			UnaryOperator<String> propertyLookup) {
		if (enabledPlugins == null || enabledPlugins.isEmpty()) {
			return null;
		}
		String defaultPlugin = null;
		for (String plugin : enabledPlugins) {
			String pattern = propertyLookup.apply(plugin + TESTCASE_PATTERN_SUFFIX);
			if (pattern == null || pattern.isBlank()) {
				if (defaultPlugin == null) {
					defaultPlugin = plugin;
				}
			} else if (testCaseName != null && Pattern.compile(pattern.trim()).matcher(testCaseName).find()) {
				return plugin;
			}
		}
		return defaultPlugin != null ? defaultPlugin : enabledPlugins.get(0);
	}
}
