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

    /**
     * Thread safety test: Verifies that concurrent access to getProvider() returns
     * consistent results across multiple threads.
     */
    @Test
    public void shouldBeThreadSafeForConcurrentAccess() throws InterruptedException, ExecutionException {
        final int numberOfThreads = 100;
        final int callsPerThread = 1000;
        ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch completionLatch = new CountDownLatch(numberOfThreads);
        List<Future<List<Provider>>> futures = new ArrayList<>();
        AtomicInteger nullProviderCount = new AtomicInteger(0);
        AtomicInteger exceptionCount = new AtomicInteger(0);

        // Submit tasks to multiple threads
        for (int i = 0; i < numberOfThreads; i++) {
            Future<List<Provider>> future = executorService.submit(() -> {
                List<Provider> providers = new ArrayList<>();
                try {
                    // Wait for all threads to be ready
                    startLatch.await();

                    // Make multiple calls to getProvider()
                    for (int j = 0; j < callsPerThread; j++) {
                        Provider provider = BouncyCastleProviderUtil.getProvider();
                        if (provider == null) {
                            nullProviderCount.incrementAndGet();
                        } else {
                            providers.add(provider);
                        }
                    }
                } catch (Exception e) {
                    exceptionCount.incrementAndGet();
                    e.printStackTrace();
                } finally {
                    completionLatch.countDown();
                }
                return providers;
            });
            futures.add(future);
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for all threads to complete
        boolean completed = completionLatch.await(30, TimeUnit.SECONDS);
        assertTrue("All threads should complete within timeout", completed);

        // Collect all providers from all threads
        List<Provider> allProviders = new ArrayList<>();
        for (Future<List<Provider>> future : futures) {
            allProviders.addAll(future.get());
        }

        // Verify no null providers were returned
        assertEquals("No null providers should be returned", 0, nullProviderCount.get());
        assertEquals("No exceptions should occur", 0, exceptionCount.get());

        // Verify all providers are the same instance
        assertFalse("Should have collected providers", allProviders.isEmpty());
        Provider firstProvider = allProviders.get(0);
        assertNotNull("First provider should not be null", firstProvider);

        // Check that all providers are the same instance
        for (Provider provider : allProviders) {
            assertSame("All threads should return the same provider instance", firstProvider, provider);
        }

        executorService.shutdown();
        assertTrue("Executor should shutdown", executorService.awaitTermination(5, TimeUnit.SECONDS));
    }

    /**
     * Thread safety test: Verifies that concurrent access doesn't cause
     * race conditions or inconsistent state.
     */
    @Test
    public void shouldBeThreadSafeUnderHighConcurrency() throws InterruptedException {
        final int numberOfThreads = 200;
        final int iterations = 5000;
        ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
        CyclicBarrier barrier = new CyclicBarrier(numberOfThreads);
        List<Provider> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger errorCount = new AtomicInteger(0);

        // Create multiple threads that will access getProvider() concurrently
        for (int i = 0; i < numberOfThreads; i++) {
            executorService.submit(() -> {
                try {
                    // Synchronize start of all threads
                    barrier.await();

                    // Perform multiple concurrent accesses
                    for (int j = 0; j < iterations; j++) {
                        Provider provider = BouncyCastleProviderUtil.getProvider();
                        if (provider == null) {
                            errorCount.incrementAndGet();
                        } else {
                            results.add(provider);
                            // Verify provider properties are consistent
                            assertEquals("Provider name should be consistent", BouncyCastleProvider.PROVIDER_NAME, provider.getName());
                        }
                    }
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                    e.printStackTrace();
                }
            });
        }

        executorService.shutdown();
        boolean completed = executorService.awaitTermination(60, TimeUnit.SECONDS);
        assertTrue("All threads should complete within timeout", completed);

        // Verify results
        assertEquals("No errors should occur during concurrent access", 0, errorCount.get());
        assertFalse("Should have collected results", results.isEmpty());

        // Verify all results are the same instance
        Provider firstProvider = results.get(0);
        long distinctInstances = results.stream().distinct().count();
        assertEquals("All threads should return the same provider instance", 1, distinctInstances);

        // Verify all instances match the first one
        for (Provider provider : results) {
            assertSame("All providers should be the same instance", firstProvider, provider);
        }
    }

    /**
     * Thread safety test: Verifies that getProvider() can be called safely
     * from multiple threads without synchronization issues.
     */
    @Test
    public void shouldHandleRapidConcurrentCalls() throws InterruptedException {
        final int numberOfThreads = 50;
        ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        List<Provider> providers = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger successCount = new AtomicInteger(0);

        // Create threads that will make rapid concurrent calls
        for (int i = 0; i < numberOfThreads; i++) {
            executorService.submit(() -> {
                try {
                    startLatch.await();

                    // Make rapid successive calls
                    for (int j = 0; j < 100; j++) {
                        Provider provider = BouncyCastleProviderUtil.getProvider();
                        if (provider != null) {
                            providers.add(provider);
                            successCount.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        executorService.shutdown();
        boolean completed = executorService.awaitTermination(10, TimeUnit.SECONDS);
        assertTrue("All threads should complete", completed);

        // Verify all calls succeeded
        assertEquals("All calls should succeed", numberOfThreads * 100, successCount.get());

        // Verify consistency
        if (!providers.isEmpty()) {
            Provider firstProvider = providers.get(0);
            for (Provider provider : providers) {
                assertSame("All providers should be the same instance", firstProvider, provider);
            }
        }
    }
}

