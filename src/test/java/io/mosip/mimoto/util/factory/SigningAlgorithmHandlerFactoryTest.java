package io.mosip.mimoto.util.factory;

import io.mosip.mimoto.constant.SigningAlgorithm;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Test cases for SigningAlgorithmHandlerFactory.
 */
public class SigningAlgorithmHandlerFactoryTest {

    @Test
    public void shouldReturnHandlerForRS256() {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(SigningAlgorithm.RS256);
        
        assertNotNull("Handler should not be null", handler);
        assertTrue("Handler should be RS256AlgorithmHandler", handler instanceof RS256AlgorithmHandler);
    }

    @Test
    public void shouldReturnHandlerForES256() {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(SigningAlgorithm.ES256);
        
        assertNotNull("Handler should not be null", handler);
        assertTrue("Handler should be ES256AlgorithmHandler", handler instanceof ES256AlgorithmHandler);
    }

    @Test
    public void shouldReturnHandlerForES256K() {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(SigningAlgorithm.ES256K);
        
        assertNotNull("Handler should not be null", handler);
        assertTrue("Handler should be ES256KAlgorithmHandler", handler instanceof ES256KAlgorithmHandler);
    }

    @Test
    public void shouldReturnHandlerForED25519() {
        SigningAlgorithmHandler handler = SigningAlgorithmHandlerFactory.getHandler(SigningAlgorithm.ED25519);
        
        assertNotNull("Handler should not be null", handler);
        assertTrue("Handler should be ED25519AlgorithmHandler", handler instanceof Ed25519AlgorithmHandler);
    }

    @Test
    public void shouldThrowExceptionWhenAlgorithmIsNull() {
        try {
            SigningAlgorithmHandlerFactory.getHandler(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention null", 
                    e.getMessage().contains("null") || e.getMessage().contains("Unsupported"));
        }
    }

    @Test
    public void shouldThrowExceptionWhenHandlerNotPresentInMap() throws Exception {
        Field handlersField = SigningAlgorithmHandlerFactory.class.getDeclaredField("handlers");
        handlersField.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<SigningAlgorithm, SigningAlgorithmHandler> handlers =
                (Map<SigningAlgorithm, SigningAlgorithmHandler>) handlersField.get(null);

        SigningAlgorithmHandler removed = handlers.remove(SigningAlgorithm.RS256);
        try {
            SigningAlgorithmHandlerFactory.getHandler(SigningAlgorithm.RS256);
            fail("Should throw IllegalArgumentException when handler is missing in map");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention unsupported", e.getMessage().contains("Unsupported"));
        } finally {
            if (removed != null) {
                handlers.put(SigningAlgorithm.RS256, removed);
            }
        }
    }
}

