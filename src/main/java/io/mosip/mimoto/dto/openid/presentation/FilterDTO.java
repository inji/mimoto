package io.mosip.mimoto.dto.openid.presentation;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FilterDTO {
    String type;
    String pattern;

    public static FilterDTOBuilder builder() {
        return new FilterDTOBuilder();
    }

    public static class FilterDTOBuilder {
        private String type;
        private String pattern;

        public FilterDTOBuilder type(String type) {
            this.type = type;
            return this;
        }

        public FilterDTOBuilder pattern(String pattern) {
            this.pattern = pattern;
            return this;
        }

        public FilterDTO build() {
            FilterDTO dto = new FilterDTO();
            dto.type = this.type;
            dto.pattern = this.pattern;
            return dto;
        }
    }
}
