package io.mosip.mimoto.exception;

import java.io.Serializable;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * This class is the entity class for the BaseUncheckedException and
 * BaseCheckedException class.
 * 
 * @author Shashank Agrawal
 * @since 1.0
 */
@NoArgsConstructor
class InfoItem implements Serializable {

    private static final long serialVersionUID = -779695043380592601L;

    @Getter
    @Setter
    public String errorCode = null;

    @Getter
    @Setter
    public String errorText = null;

    InfoItem(String errorCode, String errorText) {
        this.errorCode = errorCode;
        this.errorText = errorText;
    }

}
