package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;
import org.springframework.stereotype.Service;

@Service
public class WalletLockService {
    private final WalletPasscodeConfig walletPasscodeConfig;
    private static final int MINUTES_TO_MILLIS = 60 * 1000;

    public WalletLockService(WalletPasscodeConfig walletPasscodeConfig) {
        this.walletPasscodeConfig = walletPasscodeConfig;
    }

    public Wallet enforceLockCyclePolicy(Wallet wallet) {
        initializePasscodeControlInWallet(wallet);
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        // Increment the current attempt count
        passcodeControl.setFailedAttemptCount(passcodeControl.getFailedAttemptCount() + 1);

        if (passcodeControl.getCurrentCycleCount() == 0) {
            passcodeControl.setCurrentCycleCount(1);
        }

        if (passcodeControl.getFailedAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle()) {
            passcodeControl.setCurrentCycleCount(passcodeControl.getCurrentCycleCount() + 1);

            if (passcodeControl.getCurrentCycleCount() > walletPasscodeConfig.getMaxLockCyclesAllowed()) {
                passcodeControl.setRetryBlockedUntil(null);
                walletMetadata.setLockStatus(WalletLockStatus.PERMANENTLY_LOCKED);
            } else {
                passcodeControl.setRetryBlockedUntil(System.currentTimeMillis() + (walletPasscodeConfig.getRetryBlockedUntil() * MINUTES_TO_MILLIS));
                walletMetadata.setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
            }
        } else if (isLastSecondAttemptBeforePermanentLock(passcodeControl)) {
            walletMetadata.setLockStatus(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
        }

        return wallet;
    }

    private boolean isLastSecondAttemptBeforePermanentLock(PasscodeControl passcodeControl) {
        return passcodeControl.getFailedAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle() - 1 && passcodeControl.getCurrentCycleCount() == walletPasscodeConfig.getMaxLockCyclesAllowed();
    }

    public Wallet resetTemporaryLockIfExpired(Wallet wallet) {
        initializePasscodeControlInWallet(wallet);
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        if (isTemporaryLockExpired(walletMetadata, passcodeControl)) {
            passcodeControl.setRetryBlockedUntil(null);
            passcodeControl.setFailedAttemptCount(0);
            walletMetadata.setLockStatus(WalletLockStatus.LOCK_EXPIRED);
        }
        return wallet;
    }

    private static boolean isTemporaryLockExpired(WalletMetadata walletMetadata, PasscodeControl passcodeControl) {
        return walletMetadata.getLockStatus() == WalletLockStatus.TEMPORARILY_LOCKED && passcodeControl.getRetryBlockedUntil() != null && System.currentTimeMillis() > passcodeControl.getRetryBlockedUntil();
    }

    public Wallet resetLockState(Wallet wallet) {
        initializePasscodeControlInWallet(wallet);
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        passcodeControl.setFailedAttemptCount(0);
        passcodeControl.setCurrentCycleCount(0);
        passcodeControl.setRetryBlockedUntil(null);
        walletMetadata.setLockStatus(null);
        return wallet;
    }

    private void initializePasscodeControlInWallet(Wallet wallet) {
        PasscodeControl passcodeControl = wallet.getWalletMetadata().getPasscodeControl();
        if (passcodeControl == null) {
            wallet.getWalletMetadata().setPasscodeControl(new PasscodeControl());
        }
    }
}