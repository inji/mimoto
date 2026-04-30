/*
 * 
 * 
 * 
 * 
 */
package io.mosip.mimoto.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Crypto-With-Pin-Response model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.1.2
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-With-Pin-Response Response")
@Schema(description = "Response payload returned after encrypting or decrypting data using a PIN.")
public class CryptoWithPinResponseDto {
    /**
     * Data Encrypted/Decrypted in String
     */
    @ApiModelProperty(notes = "Data encrypted/decrypted in String")
    @Schema(description = "Encrypted or decrypted data produced by the cryptographic operation.")
    private String data;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
