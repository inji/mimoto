package io.mosip.mimoto.service;

import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class VCDownloadHandlerFactory {

    private final Map<String, VCDownloadHandler> handlers;

    public VCDownloadHandlerFactory(Map<String, VCDownloadHandler> handlers) {
        this.handlers = handlers;
    }

    public VCDownloadHandler getHandler(String version) {
        VCDownloadHandler processor = handlers.get(version);
        if (processor == null) {
            throw new IllegalArgumentException("Unsupported download version: " + version);
        }

        return processor;
    }
}