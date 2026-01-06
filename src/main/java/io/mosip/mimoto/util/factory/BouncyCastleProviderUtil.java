package io.mosip.mimoto.util.factory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;
import java.security.Security;

/**
 * Shared utility for BouncyCastle provider access.
 * Ensures single instance across all algorithm handlers.
 */
public final class BouncyCastleProviderUtil {
    
    private static final Provider BC_PROVIDER;

    static {
        Provider existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existingProvider != null) {
            BC_PROVIDER = existingProvider;
        } else {
            BC_PROVIDER = new BouncyCastleProvider();
            Security.addProvider(BC_PROVIDER);
        }
    }
    
    /**
     * Returns the BouncyCastle provider instance.
     * This is a singleton instance shared across all handlers.
     */
    public static Provider getProvider() {
        return BC_PROVIDER;
    }

    private BouncyCastleProviderUtil(){

    }
}