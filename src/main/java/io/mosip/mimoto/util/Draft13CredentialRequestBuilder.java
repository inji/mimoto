package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialDefinition;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequestProof;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class Draft13CredentialRequestBuilder {

    public Draft13VCCredentialRequest buildCredentialRequest(String format, VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {
        if (CredentialFormat.LDP_VC.getFormat().equals(format))
            return buildLdpVcCredentialRequest(proof, credentialsSupportedResponse);
        else if (CredentialFormat.VC_SD_JWT.getFormat().equals(format) || CredentialFormat.DC_SD_JWT.getFormat().equals(format))
            return buildSdJwtCredentialRequest(format, proof, credentialsSupportedResponse);
        else
            throw new IllegalArgumentException("Unsupported credential format: " + format);
    }

    private Draft13VCCredentialRequest buildLdpVcCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {
        List<String> credentialContext = credentialsSupportedResponse.getCredentialDefinition().getContext();
        if (credentialContext == null || credentialContext.isEmpty()) {
            credentialContext = List.of("https://www.w3.org/2018/credentials/v1");
        }

        return Draft13VCCredentialRequest.builder().format(CredentialFormat.LDP_VC.getFormat())
                .proof(proof)
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(credentialContext).build())
                .build();
    }

    private Draft13VCCredentialRequest buildSdJwtCredentialRequest(String format, VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {
        return Draft13VCCredentialRequest
                .builder()
                .format(format)
                .vct(credentialsSupportedResponse.getVct()).proof(proof)
                .build();
    }
}
