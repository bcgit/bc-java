package org.bouncycastle.mls.codec;

public class Varint {
    public static final long HEADER_1 = 0x00L;
    public static final long HEADER_2 = 0x4000L;
    public static final long HEADER_4 = 0x80000000L;
    public static final long MAX_1 = 0x3fL;
    public static final long MAX_2 = 0x3fffL;
    public static final long MAX_4 = 0x3fffffffL;
}
