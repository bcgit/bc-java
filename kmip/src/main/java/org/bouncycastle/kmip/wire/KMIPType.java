package org.bouncycastle.kmip.wire;

public class KMIPType
{
    private KMIPType()
    {

    }

    public static final int STRUCTURE = 0x01;
    public static final int INTEGER = 0x02;
    public static final int LONG_INTEGER = 0x03;
    public static final int BIG_INTEGER = 0x04;
    public static final int ENUMERATION = 0x05;
    public static final int BOOLEAN = 0x06;
    public static final int TEXT_STRING = 0x07;
    public static final int BYTE_STRING = 0x08;
    public static final int DATE_TIME = 0x09;
    public static final int INTERVAL = 0x0A;
}
