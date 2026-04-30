package io.mosip.mimoto.dto.resident;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "Resident service response describing the individual identifier resolution status for an AID transaction.")
public class AidStatusResponseDTO {

	@Schema(description = "Resolved individual identifier returned for the AID request.")
	private String individualId;

	@Schema(description = "Type of the resolved individual identifier.",
	        allowableValues = {"UIN", "VID"})
	private String individualIdType;

	@Schema(description = "Transaction identifier associated with the AID status lookup.")
	private String transactionID;

	@Schema(description = "Status of the AID lookup or identifier generation workflow.")
	private String aidStatus;
	
}
