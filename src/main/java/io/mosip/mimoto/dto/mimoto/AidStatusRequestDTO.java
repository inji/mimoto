package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
@Schema(description = "Request payload used to check the status of an AID transaction after OTP verification.")
public class AidStatusRequestDTO {

	@NotBlank(message = "AID is required and cannot be blank")
	@Schema(description = "Application or account identifier whose status needs to be verified.", 
	        example = "sample-aid-12345")
	private String aid;
	
	@NotBlank(message = "OTP is required and cannot be blank")
	@Schema(description = "One-time password used to authorize the AID status lookup request.", 
	        example = "123456")
	private String otp;
	
	@NotBlank(message = "Transaction ID is required and cannot be blank")
	@Schema(description = "Transaction identifier associated with the original AID request or OTP flow.", 
	        example = "txn-12345-67890")
	private String transactionID;
	
}
