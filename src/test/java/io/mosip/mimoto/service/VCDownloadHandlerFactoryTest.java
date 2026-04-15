package io.mosip.mimoto.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.HashMap;

import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.Mock;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

@ExtendWith(MockitoExtension.class)
class VCDownloadHandlerFactoryTest {
    @Mock
    private VCDownloadHandler mockDraft13Handler;

    private VCDownloadHandlerFactory factory;

    @BeforeEach
    void setUp() {
        Map<String, VCDownloadHandler> handlers = new HashMap<>();
        handlers.put("draft-13", mockDraft13Handler);
        factory = new VCDownloadHandlerFactory(handlers);
    }

    @Test
    void shouldReturnHandlerForValidVersion() {
        VCDownloadHandler handler = factory.getHandler("draft-13");
        assertNotNull(handler);
        assertEquals(mockDraft13Handler, handler);
    }

    @Test
    void shouldThrowExceptionForUnsupportedVersion() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> factory.getHandler("unsupported"));
        assertEquals("Unsupported download version: unsupported", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionForNullVersion() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> factory.getHandler(null));
        assertEquals("Unsupported download version: null", exception.getMessage());
    }
}