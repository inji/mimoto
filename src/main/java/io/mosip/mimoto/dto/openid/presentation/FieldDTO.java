package io.mosip.mimoto.dto.openid.presentation;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FieldDTO {
    String[] path;
    FilterDTO filter;

    public static FieldDTOBuilder builder() {
        return new FieldDTOBuilder();
    }

    public static class FieldDTOBuilder {
        private String[] path;
        private FilterDTO filter;

        public FieldDTOBuilder path(String[] path) {
            this.path = path;
            return this;
        }

        public FieldDTOBuilder filter(FilterDTO filter) {
            this.filter = filter;
            return this;
        }

        public FieldDTO build() {
            FieldDTO dto = new FieldDTO();
            dto.path = this.path;
            dto.filter = this.filter;
            return dto;
        }
    }
}
