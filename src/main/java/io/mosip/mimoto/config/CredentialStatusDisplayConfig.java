package io.mosip.mimoto.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

/**
 * Maps credential status display values to PDF/SVG color and icon assets.
 */
@Slf4j
@Component
public class CredentialStatusDisplayConfig {

    public String statusColor(String status) {
        return switch (status) {
            case "Revoked" -> "#C62828";
            case "Suspended" -> "#7866DF";
            case "Expired" -> "#E65100";
            case "Pending" -> "#5F6368";
            default -> "#2E7D32";
        };
    }

    public String statusIconDataUri(String status) {
        String file = switch (status) {
            case "Pending" -> "pending.svg";
            case "Revoked" -> "revoked.svg";
            case "Suspended" -> "suspended.png";
            case "Expired" -> "expired.svg";
            default -> "valid.svg";
        };
        String mediaType = file.endsWith(".png") ? "image/png" : "image/svg+xml";
        try (InputStream in = getClass().getResourceAsStream("/status-icons/" + file)) {
            if (in == null) {
                return "";
            }
            return "data:" + mediaType + ";base64," + Base64.getEncoder().encodeToString(in.readAllBytes());
        } catch (IOException e) {
            log.warn("Unable to load status icon {}", file, e);
            return "";
        }
    }
}
