package io.mosip.mimoto.util.factory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * Test cases for BouncyCastleProviderUtil.
 */
public class BouncyCastleProviderUtilTest {

    @Test
    public void shouldReturnValidBouncyCastleProvider() {
        Provider provider = BouncyCastleProviderUtil.getProvider();

        assertNotNull("Provider should not be null", provider);
        assertTrue("Provider should be instance of BouncyCastleProvider", provider instanceof BouncyCastleProvider);
        assertEquals("Provider name should be BC", BouncyCastleProvider.PROVIDER_NAME, provider.getName());
        
        Provider registeredProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull("BouncyCastle provider should be registered", registeredProvider);
        assertEquals("Registered provider name should match", BouncyCastleProvider.PROVIDER_NAME, registeredProvider.getName());
    }

    @Test
    public void shouldReturnSameInstanceOnMultipleCalls() {
        Provider provider1 = BouncyCastleProviderUtil.getProvider();
        Provider provider2 = BouncyCastleProviderUtil.getProvider();

        assertNotNull("Provider should not be null", provider1);
        assertSame("Should return the same instance", provider1, provider2);
    }
}

