package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Internal request payload used to fetch the status of an AID workflow.")
public class InternalAidStatusDTO {

	@NotBlank(message = "Individual ID is required and cannot be blank")
	@Schema(description = "Resolved or supplied individual identifier.")
	private String individualId;
	@NotBlank(message = "OTP is required and cannot be blank")
	@Schema(description = "One-time password used to authorize the AID status request.")
	private String otp;
	@NotBlank(message = "Transaction ID is required and cannot be blank")
	@Schema(description = "Transaction identifier associated with the AID status request.")
	private String transactionId;
	
}
