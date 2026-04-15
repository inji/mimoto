package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.VCSpecificationVersion;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class VCDownloadHandlerFactory {

    private final Map<String, VCDownloadHandler> handlers;

    public VCDownloadHandlerFactory(Map<String, VCDownloadHandler> handlers) {
        this.handlers = handlers;
    }

    public VCDownloadHandler getHandler(VCSpecificationVersion version) {
        if(version == null) {
            throw new NullPointerException("Version cannot be null");
        }
        VCDownloadHandler processor = handlers.get(version.getVersion());
        if (processor == null) {
            throw new IllegalArgumentException("Unsupported download version: " + version);
        }

        return processor;
    }
}