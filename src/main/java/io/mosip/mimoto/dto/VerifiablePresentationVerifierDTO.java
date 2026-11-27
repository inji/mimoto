package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

@Data
@AllArgsConstructor
@Schema(description = "Verifier details returned for an OpenID4VP presentation request so the wallet can show who is asking for credentials.")
public class VerifiablePresentationVerifierDTO {

    @Schema(description = "Unique identifier (client_id) of the Verifier",
            example = "mock-client")
    private String id;

    @Schema(description = "Name of the Verifier",
            example = "Requester name")
    private String name;

    @URL
    @Schema(description = "Logo URL of the Verifier",
            example = "https://api.collab.mosip.net/inji/verifier-logo.png")
    private String logo;

    @Schema(description = "Indicates if the Verifier is trusted by the User through the wallet",
            example = "true")
    private boolean isTrusted;

    @Schema(description = "Indicates if the Verifier is pre-registered with the wallet",
            example = "true")
    private boolean isPreregisteredWithWallet;

    @URL
    @Schema(description = "Redirect URI used to redirect the User back to the Verifier after the presentation is completed",
            example = "https://injiverify.collab.mosip.net/redirect")
    private String redirectUri;

    @Schema(description = "Client identifier scheme used by the Verifier",
            example = "x509_san_dns", allowableValues = {"pre-registered", "x509_san_dns"})
    private String clientIdScheme;

    @Schema(description = "DNS name verified from the Verifier's certificate SAN — present only when clientIdScheme is x509_san_dns",
            example = "verifier.example.com")
    private String certVerifiedDnsName;

    @Schema(description = "Organization name from the Verifier's certificate — present only when clientIdScheme is x509_san_dns",
            example = "Example Verifier Inc.")
    private String certOrganization;

    @Schema(description = "Expiry date of the Verifier's certificate in ISO 8601 format — present only when clientIdScheme is x509_san_dns",
            example = "2027-06-01T00:00:00Z")
    private String certValidUntil;
}
