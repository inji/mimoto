package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConstraintsDTO {
    FieldDTO[] fields;

    @JsonProperty("limitDisclosure")
    private String limitDisclosure;

    public static ConstraintsDTOBuilder builder() {
        return new ConstraintsDTOBuilder();
    }

    public static class ConstraintsDTOBuilder {
        private FieldDTO[] fields;
        private String limitDisclosure;

        public ConstraintsDTOBuilder fields(FieldDTO[] fields) {
            this.fields = fields;
            return this;
        }

        public ConstraintsDTOBuilder limitDisclosure(String limitDisclosure) {
            this.limitDisclosure = limitDisclosure;
            return this;
        }

        public ConstraintsDTO build() {
            ConstraintsDTO dto = new ConstraintsDTO();
            dto.fields = this.fields;
            dto.limitDisclosure = this.limitDisclosure;
            return dto;
        }
    }
}
