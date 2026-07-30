package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PresentationRequestDTO {

    @JsonProperty("response_type")
    String responseType;
    String resource;
    @JsonProperty("presentation_definition")
    PresentationDefinitionDTO presentationDefinition;
    @JsonProperty("client_id")
    String clientId;
    @JsonProperty("redirect_uri")
    String redirectUri;
    @JsonProperty("state")
    String state;
    @JsonProperty("nonce")
    String nonce;
    @JsonProperty("response_uri")
    String responseUri;
    @JsonProperty("response_mode")
    String responseMode;
    @JsonProperty("dcql_query")
    String dcqlQuery;

}
