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
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Crypto-With-Pin-Request model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.1.2
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-With-Pin-Service Request")
@Schema(description = "Request payload used to encrypt or decrypt data with a user-provided PIN.")
public class CryptoWithPinRequestDto {

    /**
     * Data in String to encrypt/decrypt
     */

    @ApiModelProperty(notes = "Data in String to encrypt/decrypt", required = true)
    @Schema(description = "Plaintext or ciphertext data to encrypt or decrypt.")
    @NotBlank
    private String data;

    /**
     * Pin to be used for encrypt/decrypt
     */
    @ApiModelProperty(notes = " Pin to be used for encrypt/decrypt", required = true, example = "A1234")
    @Schema(description = "User PIN used as part of the encryption or decryption operation.")
    @NotBlank
    private String userPin;

    public void setData(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setUserPin(String userPin) {
        this.userPin = userPin;
    }

    public String getUserPin() {
        return userPin;
    }
}
