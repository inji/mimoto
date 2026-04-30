package io.mosip.mimoto.dto.openid.presentation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class InputDescriptorDTO {
    String id;
    Map<String, Map<String, List<String>>> format;
    ConstraintsDTO constraints;

    public Map<String, Map<String, List<String>>> getFormat() {
        return format;
    }

    public static InputDescriptorDTOBuilder builder() {
        return new InputDescriptorDTOBuilder();
    }

    public static class InputDescriptorDTOBuilder {
        private String id;
        private Map<String, Map<String, List<String>>> format;
        private ConstraintsDTO constraints;

        public InputDescriptorDTOBuilder id(String id) {
            this.id = id;
            return this;
        }

        public InputDescriptorDTOBuilder format(Map<String, Map<String, List<String>>> format) {
            this.format = format;
            return this;
        }

        public InputDescriptorDTOBuilder constraints(ConstraintsDTO constraints) {
            this.constraints = constraints;
            return this;
        }

        public InputDescriptorDTO build() {
            InputDescriptorDTO dto = new InputDescriptorDTO();
            dto.id = this.id;
            dto.format = this.format;
            dto.constraints = this.constraints;
            return dto;
        }
    }
}
