package io.mosip.mimoto.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatusCheck implements Serializable {
    private String purpose;
    private boolean valid;
}
