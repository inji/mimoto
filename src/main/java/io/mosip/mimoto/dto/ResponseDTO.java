package io.mosip.mimoto.dto;

import java.io.Serializable;
import java.util.Arrays;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Binary response payload wrapper, typically used for generated files.")
public class ResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    @Schema(description = "File content represented as a byte array.")
    private byte[] file;

    public byte[] getFile() {
        if (file != null)
            return Arrays.copyOf(file, file.length);
        return null;
    }

    public void setFile(byte[] file) {
        this.file = file != null ? file : null;
    }

}
