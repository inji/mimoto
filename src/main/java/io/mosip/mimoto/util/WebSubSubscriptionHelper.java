package io.mosip.mimoto.util;

import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.kernel.core.websub.spi.SubscriptionClient;
import io.mosip.kernel.websub.api.exception.WebSubClientException;
import io.mosip.kernel.websub.api.model.SubscriptionChangeRequest;
import io.mosip.kernel.websub.api.model.SubscriptionChangeResponse;
import io.mosip.kernel.websub.api.model.UnsubscriptionRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class WebSubSubscriptionHelper {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(WebSubSubscriptionHelper.class);

    @Value("${mosip.event.hub.subUrl}")
    private String webSubHubSubUrl;

    @Value("${mosip.event.hub.pubUrl}")
    private String webSubHubPubUrl;

    @Value("${mosip.event.secret}")
    private String webSubSecret;

    @Value("${mosip.event.callBackUrl}")
    private String callBackUrl;

    @Value("${mosip.event.topic}")
    private String topic;

    @Autowired
    SubscriptionClient<SubscriptionChangeRequest, UnsubscriptionRequest, SubscriptionChangeResponse> sb;

    @Autowired
    private PublisherClient<String, Object, HttpHeaders> pb;

    @Scheduled(
        fixedDelayString    = "${websub-resubscription-delay-millisecs}",
        initialDelayString  = "${mosip.event.delay-millisecs}"
    )
    public void initSubscriptions() {
        log.info("Initializing subscriptions...");
        subscribeEvent(topic, callBackUrl, webSubSecret);
    }

    public SubscriptionChangeResponse unSubscribeEvent(String topic, String callBackUrl) {
        try {
            UnsubscriptionRequest unsubscriptionRequest = new UnsubscriptionRequest();
            unsubscriptionRequest.setCallbackURL(callBackUrl);
            unsubscriptionRequest.setHubURL(webSubHubSubUrl);
            unsubscriptionRequest.setTopic(topic);
            log.info("Unsubscription request : ");
            return sb.unSubscribe(unsubscriptionRequest);
        } catch (WebSubClientException e) {
            log.info("Websub unsubscription error: {} ", e.getMessage());
        }
        return null;
    }

    public SubscriptionChangeResponse subscribeEvent(String topic, String callBackUrl, String secret) {
        try {
            SubscriptionChangeRequest subscriptionRequest = new SubscriptionChangeRequest();
            subscriptionRequest.setCallbackURL(callBackUrl);
            subscriptionRequest.setHubURL(webSubHubSubUrl);
            subscriptionRequest.setSecret(secret);
            subscriptionRequest.setTopic(topic);
            log.info("Subscription request : ");
            return sb.subscribe(subscriptionRequest);
        } catch (WebSubClientException e) {
            log.info("Websub subscription error: {}", e.getMessage());
        }
        return null;
    }

    public void publish(String topic, Object payload) {
        try {
            HttpHeaders headers = new HttpHeaders();
            pb.publishUpdate(topic, payload, MediaType.APPLICATION_JSON_UTF8_VALUE, headers, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            log.info("Websub publish update error: {}", e.getMessage());
        }

    }

    @Cacheable(value = "topics", key = "{#topic}")
    public void registerTopic(String topic) {
        try {
            pb.registerTopic(topic, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            log.info("Topic already registered: {}", e.getMessage());
        }

    }

    @Cacheable(value = "topics", key = "{#topic}")
    public void unRegisterTopic(String topic) {
        try {
            pb.unregisterTopic(topic, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            log.info("Topic already unregistered: {}", e.getMessage());
        }

    }
}
