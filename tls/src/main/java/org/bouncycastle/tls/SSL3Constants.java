package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;

public class SSL3Constants
{
    private static final byte IPAD_BYTE = (byte)0x36;
    private static final byte OPAD_BYTE = (byte)0x5C;

    private static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    public static byte[] getInputPad()
    {
        return IPAD.clone();
    }

    public static byte[] getOutputPad()
    {
        return OPAD.clone();
    }
}
