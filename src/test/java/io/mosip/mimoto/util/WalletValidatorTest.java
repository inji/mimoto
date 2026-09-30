package io.mosip.mimoto.util;

import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WalletValidator.class)
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletValidatorTest {

    @Autowired
    private WalletValidator walletValidator;

    @Test
    void testValidateWalletRequest_validData() {
        walletValidator.validateUserId("user1");
        walletValidator.validateWalletName("wallet1");
        walletValidator.validateWalletPin("123456");
    }

    @Test
    void testValidatePin_invalidPin() {
        walletValidator.validateUserId("user1");
        walletValidator.validateWalletName("My Wallet");
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletValidator.validateWalletPin("12"));

        assertEquals("invalid_request --> PIN must be numeric with 6 digits", exception.getMessage());
    }

    @Test
    void testValidateWalletName_invalidName() {
        walletValidator.validateUserId("user1");
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletValidator.validateWalletName("My Wallet!@"));

        assertEquals("invalid_request --> Wallet name must be alphanumeric with allowed special characters", exception.getMessage());
    }

    @Test
    void testValidateWalletName_validName() {
        walletValidator.validateWalletName("My Wallet 123");
    }

    @Test
    void testValidateUserId_nullUserId() {
        UnauthorizedAccessException exception = assertThrows(UnauthorizedAccessException.class, () -> {
            walletValidator.validateUserId(null);
        });

        assertEquals("unauthorized --> User ID not found in session", exception.getMessage());
    }
}
