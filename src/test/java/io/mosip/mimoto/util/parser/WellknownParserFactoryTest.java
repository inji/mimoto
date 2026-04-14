package io.mosip.mimoto.util.parser;

import io.mosip.mimoto.constant.VCSpecificationVersion;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WellknownParserFactoryTest {

    private WellknownParserFactory factory;
    private WellknownResponseParser v1Parser;
    private WellknownResponseParser draft13Parser;

    @BeforeEach
    void setUp() {
        v1Parser = new StubParser(VCSpecificationVersion.V1);
        draft13Parser = new StubParser(VCSpecificationVersion.DRAFT_13);
        factory = new WellknownParserFactory(List.of(v1Parser, draft13Parser));
    }

    @Test
    void shouldReturnV1ParserForV1Version() {
        WellknownResponseParser parser = factory.getParser(VCSpecificationVersion.V1);
        assertSame(v1Parser, parser);
    }

    @Test
    void shouldReturnDraft13ParserForDraft13Version() {
        WellknownResponseParser parser = factory.getParser(VCSpecificationVersion.DRAFT_13);
        assertSame(draft13Parser, parser);
    }

    @Test
    void shouldThrowExceptionForUnregisteredVersion() {
        WellknownParserFactory singleParserFactory = new WellknownParserFactory(List.of(v1Parser));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> singleParserFactory.getParser(VCSpecificationVersion.DRAFT_13));

        assertTrue(exception.getMessage().contains("DRAFT_13"));
    }

    @Test
    void shouldHandleEmptyParserList() {
        WellknownParserFactory emptyFactory = new WellknownParserFactory(List.of());

        assertThrows(IllegalArgumentException.class,
                () -> emptyFactory.getParser(VCSpecificationVersion.V1));
    }

    private static class StubParser implements WellknownResponseParser {
        private final VCSpecificationVersion version;

        StubParser(VCSpecificationVersion version) {
            this.version = version;
        }

        @Override
        public VCSpecificationVersion getSupportedVersion() {
            return version;
        }

        @Override
        public CredentialIssuerWellKnownResponse parse(String jsonResponse) throws IOException {
            return new CredentialIssuerWellKnownResponse();
        }

        @Override
        public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws InvalidWellknownResponseException {
        }
    }
}
