package io.mosip.mimoto.util.factory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Test cases for BouncyCastleProviderUtil.
 */
public class BouncyCastleProviderUtilTest {

    @Test
    public void shouldReturnProviderInstance() {
        Provider provider = BouncyCastleProviderUtil.getProvider();

        assertNotNull("Provider should not be null", provider);
        assertTrue("Provider should be instance of BouncyCastleProvider", provider instanceof BouncyCastleProvider);
    }

    @Test
    public void shouldReturnSameInstanceOnMultipleCalls() {
        Provider provider1 = BouncyCastleProviderUtil.getProvider();
        Provider provider2 = BouncyCastleProviderUtil.getProvider();

        assertSame("Should return the same instance", provider1, provider2);
    }

    @Test
    public void shouldHaveProviderRegisteredInSecurity() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

        assertNotNull("BouncyCastle provider should be registered", provider);
        assertEquals("Provider name should match", BouncyCastleProvider.PROVIDER_NAME, provider.getName());
    }

    @Test
    public void shouldReturnProviderWithCorrectName() {
        Provider provider = BouncyCastleProviderUtil.getProvider();

        assertEquals("Provider name should be BC", BouncyCastleProvider.PROVIDER_NAME, provider.getName());
    }

    @Test
    public void shouldNotReturnNullProvider() {
        Provider provider = BouncyCastleProviderUtil.getProvider();

        assertNotNull("Provider should never be null", provider);
    }
}

