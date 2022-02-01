package org.bouncycastle.jsse.provider;

import java.net.IDN;

public class IDNUtil
{
    public static final int ALLOW_UNASSIGNED = IDN.ALLOW_UNASSIGNED;
    public static final int USE_STD3_ASCII_RULES = IDN.USE_STD3_ASCII_RULES;

    public static String toASCII(String input, int flag)
    {
        return IDN.toASCII(input, flag);
    }

    public static String toUnicode(String input, int flag)
    {
        return IDN.toUnicode(input, flag);
    }
}
