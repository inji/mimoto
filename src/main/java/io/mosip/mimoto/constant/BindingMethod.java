package io.mosip.mimoto.constant;

public enum BindingMethod {
    JWK("jwk"),
    DID_JWK("did:jwk"),
    DID_KEY("did:key");

    private final String value;

    BindingMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static BindingMethod fromString(String value) {
        for (BindingMethod method : values()) {
            if (method.value.equalsIgnoreCase(value)) {
                return method;
            }
        }
        throw new IllegalArgumentException("Unsupported binding method: " + value);
    }
}