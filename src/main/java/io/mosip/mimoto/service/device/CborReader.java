package io.mosip.mimoto.service.device;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, strict CBOR (RFC 8949) reader for App Attest attestation objects.
 * <p>
 * Supports definite-length unsigned/negative integers, byte and text strings, arrays, maps, tags (unwrapped)
 * and the simple values false/true/null. Byte strings decode to {@code byte[]}, text strings to {@link String},
 * integers to {@link Long}, arrays to {@link List} and maps to {@link Map}. Anything else is rejected.
 */
final class CborReader {

    private static final int MAX_DEPTH = 16;

    private final byte[] data;
    private int position;

    CborReader(byte[] data, int offset) {
        this.data = data;
        this.position = offset;
    }

    /** Decodes a whole buffer that must hold exactly one CBOR item. */
    static Object decodeSingle(byte[] data) {
        CborReader reader = new CborReader(data, 0);
        Object value = reader.read();
        if (reader.position != data.length) {
            throw new IllegalArgumentException("Trailing bytes after CBOR item");
        }
        return value;
    }

    int position() {
        return position;
    }

    Object read() {
        return read(0);
    }

    private Object read(int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("CBOR nesting too deep");
        }
        int initial = readUnsignedByte();
        int majorType = initial >>> 5;
        int info = initial & 0x1f;
        if (majorType == 7) {
            return switch (info) {
                case 20 -> Boolean.FALSE;
                case 21 -> Boolean.TRUE;
                case 22 -> null;
                default -> throw new IllegalArgumentException("Unsupported CBOR simple value " + info);
            };
        }
        long argument = readArgument(info);
        return switch (majorType) {
            case 0 -> nonNegative(argument);
            case 1 -> -1 - nonNegative(argument);
            case 2 -> readBytes(length(argument));
            case 3 -> new String(readBytes(length(argument)), StandardCharsets.UTF_8);
            case 4 -> {
                int size = length(argument);
                List<Object> list = new ArrayList<>(Math.min(size, 64));
                for (int i = 0; i < size; i++) {
                    list.add(read(depth + 1));
                }
                yield list;
            }
            case 5 -> {
                int size = length(argument);
                Map<Object, Object> map = new LinkedHashMap<>();
                for (int i = 0; i < size; i++) {
                    Object key = read(depth + 1);
                    if (map.containsKey(key)) {
                        throw new IllegalArgumentException("Duplicate CBOR map key");
                    }
                    map.put(key, read(depth + 1));
                }
                yield map;
            }
            case 6 -> read(depth + 1);
            default -> throw new IllegalStateException("Unreachable CBOR major type " + majorType);
        };
    }

    private long readArgument(int info) {
        if (info < 24) {
            return info;
        }
        int bytes = switch (info) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            case 27 -> 8;
            default -> throw new IllegalArgumentException("Unsupported CBOR additional info " + info);
        };
        long value = 0;
        for (int i = 0; i < bytes; i++) {
            value = (value << 8) | readUnsignedByte();
        }
        return value;
    }

    private static long nonNegative(long argument) {
        if (argument < 0) {
            throw new IllegalArgumentException("CBOR integer out of range");
        }
        return argument;
    }

    private int length(long argument) {
        if (argument < 0 || argument > data.length - position) {
            throw new IllegalArgumentException("CBOR length exceeds input");
        }
        return (int) argument;
    }

    private int readUnsignedByte() {
        if (position >= data.length) {
            throw new IllegalArgumentException("Unexpected end of CBOR input");
        }
        return data[position++] & 0xff;
    }

    private byte[] readBytes(int length) {
        byte[] bytes = Arrays.copyOfRange(data, position, position + length);
        position += length;
        return bytes;
    }
}
