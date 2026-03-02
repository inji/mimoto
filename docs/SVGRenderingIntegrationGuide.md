# SVG rendering integration guide

Mimoto service now supports rendering VCs using an issuer-controlled SVG template. It is W3C Verifiable Credential Rendering specification compliant and currently it is implemented for W3C JSON-LD VC 2.0.

## Pre-requisites :
- The VC should be a valid W3C JSON-LD VC 2.0 credential.
- In the VC, renderMethod field should be present and renderSuite field in it should be set to `svg-mustache`. Along with it there should be information regarding the hosted template :
    ```json
    "renderMethod": {
            "type": "TemplateRenderMethod",
            "renderSuite": "svg-mustache",
            "template": {
                "id": "https://issuer-host.com/assets/templates/template.svg",
                "mediaType": "image/svg+xml",
                "digestMultibase": "zQmerWC85Wg6wFl9znFCwYxApG270iEu5h6JqWAPdhyxz2dR"
            }
    }
    ```
    Reference : https://www.w3.org/TR/vc-render-method/
- The template should be hosted on a publicly accessible URL and should be a valid SVG file. The placeholders in the template should be strictly compliant to JSON Pointer Algorithm as mentioned in the specification.

## High-level user flow :
1. User downloads the VC either in guest mode or from their wallet.
2. Mimoto service checks for the presence of renderMethod field in the VC and if its renderSuite is `svg-mustache`.
3. inji-vc-renderer library is invoked, it fetches the template from the URL mentioned in template field and verifies the integrity of the template using the digestMultibase value.
4. The library then renders the VC using the fetched template and the data from the VC. The library replaces the placeholders in the template with the corresponding values from the VC.
5. The inji-vc-renderer library returns the rendered SVG to Mimoto service. Mimoto service then invokes the library again to convert the SVG to PDF, and returns the PDF to the user.

    ```mermaid
    sequenceDiagram
        participant User
        participant Mimoto Service
        participant inji-vc-renderer 
        participant Issuer
        
        User->>Mimoto Service: Download VC
        Mimoto Service->>Mimoto Service: Check for VC format, renderMethod field and renderSuite value
        alt eligible for SVG rendering
            Mimoto Service->>inji-vc-renderer: Send VC data (and QR code data if OnlineSharing type)
            inji-vc-renderer->>Issuer: Fetch template from URL
            Issuer-->>inji-vc-renderer: Return template
            inji-vc-renderer->inji-vc-renderer: Verify integrity of template using digestMultibase
            inji-vc-renderer->>inji-vc-renderer: Replace placeholders with VC data
            inji-vc-renderer-->>Mimoto Service: Return rendered SVG
            Mimoto Service->>inji-vc-renderer: Convert SVG to PDF
            inji-vc-renderer-->>Mimoto Service: Return PDF
            Mimoto Service-->>User: Send PDF back to user
        else not eligible for SVG rendering
            Mimoto Service->>Mimoto Service: Handle using existing rendering logic (e.g., using custom HTML templates)
            Mimoto Service-->>User: Send rendered credential PDF back to user
        end
    ```

More details about the SVG template rendering implementation can be found in the codebase of inji-vc-renderer library : https://github.com/inji/inji-vc-renderer/blob/master/kotlin/Readme.md

## Error scenarios :
- If the template cannot be fetched from the URL, an error message is returned to the user indicating that the template could not be retrieved.
- If the integrity of the template cannot be verified using the digestMultibase value, an error message is returned to the user indicating that the template integrity verification failed.

-----------

## References :
- [W3C Verifiable Credential Rendering specification](https://www.w3.org/TR/vc-render-method/)
- [inji-vc-renderer Kotlin library](https://github.com/inji/inji-vc-renderer/blob/master/kotlin/Readme.md)
