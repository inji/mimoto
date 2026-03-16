package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.config.WalletPasscodeConfigTest;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {WalletPasscodeConfigTest.class, WalletLockService.class})
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletLockServiceTest {

    @Autowired
    private WalletLockService walletLockService;

    @Autowired
    private WalletPasscodeConfig walletPasscodeConfig;

    private Wallet wallet;

    @Before
    public void setUp() {
        String userId = UUID.randomUUID().toString();
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(0, 0, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);
    }

    @Test
    public void testWalletPasscodeConfigInitialization() {
        assertNotNull(walletPasscodeConfig, "WalletPasscodeConfig should be initialized");
        assertEquals(60, walletPasscodeConfig.getRetryBlockedUntil(), "RetryBlockedUntil should be 60 minutes");
        assertEquals(5, walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle(), "MaxFailedAttemptsAllowedPerCycle should be 5");
        assertEquals(3, walletPasscodeConfig.getMaxLockCyclesAllowed(), "MaxLockCyclesAllowed should be 3");
    }

    @Test
    public void enforceLockCyclePolicyShouldTemporarilyLockWalletOnInvalidLastAttemptInCurrentCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(4);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(1);

        Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertTrue(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil() > System.currentTimeMillis());
    }

    @Test
    public void enforceLockCyclePolicyShouldPermanentlyLockWalletOnInvalidLastAttemptInLastCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(4);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.PERMANENTLY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void enforceLockCyclePolicyShouldSetStatusToLastAttemptBeforeLockoutOnInvalidPenultimateAttempt() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(3);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT, updatedWallet.getWalletMetadata().getLockStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsExpired() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() - 1000);

        Wallet updatedWallet = walletLockService.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.LOCK_EXPIRED, updatedWallet.getWalletMetadata().getLockStatus());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsNotExpired() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() + 1000);

        Wallet updatedWallet = walletLockService.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertEquals(wallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount(),
                updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
    }

    @Test
    public void testResetLockState() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(6);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(2);
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);

        Wallet updatedWallet = walletLockService.resetLockState(wallet);

        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertNull(updatedWallet.getWalletMetadata().getLockStatus());
    }

    @Test
    public void enforceLockCyclePolicyShouldInitializeCycleCountWhenCurrentCycleCountIsZero() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(0);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(0);

        Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(wallet);

        assertEquals(1, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount());
        assertEquals(1, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
    }

    @Test
    public void enforceLockCyclePolicyShouldNotSetLastAttemptStatusWhenConditionsNotMet() {
        // Test scenarios where LAST_ATTEMPT_BEFORE_LOCKOUT should NOT be set
        // Format: {initialFailedCount, currentCycle, expectedFailedCountAfter, description}
        Object[][] testCases = {
                {2, 3, 3, "neither penultimate attempt nor last cycle"},
                {3, 2, 4, "penultimate attempt but not last cycle"},
                {1, 3, 2, "last cycle but not penultimate attempt"}
        };

        for (Object[] testCase : testCases) {
            int initialFailedCount = (int) testCase[0];
            int currentCycle = (int) testCase[1];
            int expectedFailedCountAfter = (int) testCase[2];
            String description = (String) testCase[3];

            // Reset wallet for each test case
            String userId = UUID.randomUUID().toString();
            PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(initialFailedCount, currentCycle, null);
            WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
            Wallet testWallet = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);

            Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(testWallet);

            assertNotEquals(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT, 
                    updatedWallet.getWalletMetadata().getLockStatus(),
                    "Should NOT set LAST_ATTEMPT_BEFORE_LOCKOUT when " + description);
            assertEquals(expectedFailedCountAfter, 
                    updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount(),
                    "Failed attempt count mismatch when " + description);
        }
    }

    @Test
    public void testResetTemporaryLockIfLockStatusIsNotTemporarilyLocked() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.PERMANENTLY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() - 1000);

        Wallet updatedWallet = walletLockService.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.PERMANENTLY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfRetryBlockedUntilIsNull() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(null);

        Wallet updatedWallet = walletLockService.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void enforceLockCyclePolicyShouldInitializePasscodeControlWhenNull() {
        String userId = UUID.randomUUID().toString();
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", null, null);
        Wallet walletWithNullPasscode = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);

        assertNull(walletWithNullPasscode.getWalletMetadata().getPasscodeControl());

        Wallet updatedWallet = walletLockService.enforceLockCyclePolicy(walletWithNullPasscode);

        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl());
        assertEquals(1, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
        assertEquals(1, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount());
    }

    @Test
    public void shouldInitializePasscodeControlWhenNullForAllMethods() {
        Object[][] testCases = {
                {"enforceLockCyclePolicy", 1, 1},
                {"resetTemporaryLockIfExpired", null, null},
                {"resetLockState", 0, 0}
        };

        for (Object[] testCase : testCases) {
            String methodName = (String) testCase[0];
            Integer expectedFailedCount = (Integer) testCase[1];
            Integer expectedCycleCount = (Integer) testCase[2];

            String userId = UUID.randomUUID().toString();
            WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", null, null);
            Wallet walletWithNullPasscode = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);

            assertNull(walletWithNullPasscode.getWalletMetadata().getPasscodeControl(),
                    "PasscodeControl should be null before calling " + methodName);

            Wallet updatedWallet;
            switch (methodName) {
                case "enforceLockCyclePolicy":
                    updatedWallet = walletLockService.enforceLockCyclePolicy(walletWithNullPasscode);
                    break;
                case "resetTemporaryLockIfExpired":
                    updatedWallet = walletLockService.resetTemporaryLockIfExpired(walletWithNullPasscode);
                    break;
                case "resetLockState":
                    updatedWallet = walletLockService.resetLockState(walletWithNullPasscode);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown method: " + methodName);
            }

            assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl(),
                    "PasscodeControl should be initialized after calling " + methodName);

            if (expectedFailedCount != null) {
                assertEquals(expectedFailedCount,
                        updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount(),
                        "Failed attempt count mismatch for " + methodName);
            }
            if (expectedCycleCount != null) {
                assertEquals(expectedCycleCount,
                        updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount(),
                        "Current cycle count mismatch for " + methodName);
            }
        }
    }
}