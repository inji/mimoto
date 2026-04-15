package io.mosip.mimoto.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.HashMap;

import io.mosip.mimoto.constant.VCSpecificationVersion;
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
        handlers.put(VCSpecificationVersion.DRAFT_13.getVersion(), mockDraft13Handler);
        factory = new VCDownloadHandlerFactory(handlers);
    }

    @Test
    void shouldReturnHandlerForValidVersion() {
        VCDownloadHandler handler = factory.getHandler(VCSpecificationVersion.DRAFT_13);
        assertNotNull(handler);
        assertEquals(mockDraft13Handler, handler);
    }

    @Test
    void shouldThrowExceptionForUnsupportedVersion() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> factory.getHandler(VCSpecificationVersion.V1));
        assertEquals("Unsupported download version: V1", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionForNullVersion() {
        NullPointerException exception = assertThrows(NullPointerException.class,
            () -> factory.getHandler(null));
        assertEquals("Version cannot be null", exception.getMessage());
    }
}