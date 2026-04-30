package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PresentationDefinitionDTO {

    String id;
    @JsonProperty("input_descriptors")
    List<InputDescriptorDTO> inputDescriptors;

    public List<InputDescriptorDTO> getInputDescriptors() {
        return inputDescriptors;
    }

    public static PresentationDefinitionDTOBuilder builder() {
        return new PresentationDefinitionDTOBuilder();
    }

    public static class PresentationDefinitionDTOBuilder {
        private String id;
        private List<InputDescriptorDTO> inputDescriptors;

        public PresentationDefinitionDTOBuilder id(String id) {
            this.id = id;
            return this;
        }

        public PresentationDefinitionDTOBuilder inputDescriptors(List<InputDescriptorDTO> inputDescriptors) {
            this.inputDescriptors = inputDescriptors;
            return this;
        }

        public PresentationDefinitionDTO build() {
            PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
            dto.id = this.id;
            dto.inputDescriptors = this.inputDescriptors;
            return dto;
        }
    }
}
