package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class KeyShareEntry
{
    private static boolean checkKeyExchangeLength(int length)
    {
        return 0 < length && length < (1 << 16);
    }

    protected final int namedGroup;
    protected final byte[] keyExchange;

    /**
     * @param namedGroup
     *            {@link NamedGroup}
     * @param keyExchange
     */
    public KeyShareEntry(int namedGroup, byte[] keyExchange)
    {
        if (!TlsUtils.isValidUint16(namedGroup))
        {
            throw new IllegalArgumentException("'namedGroup' should be a uint16");
        }
        if (null == keyExchange)
        {
            throw new NullPointerException("'keyExchange' cannot be null");
        }
        if (!checkKeyExchangeLength(keyExchange.length))
        {
            throw new IllegalArgumentException("'keyExchange' must have length from 1 to (2^16 - 1)");
        }

        this.namedGroup = namedGroup;
        this.keyExchange = keyExchange;
    }

    /**
     * @return {@link NamedGroup}
     */
    public int getNamedGroup()
    {
        return namedGroup;
    }

    public byte[] getKeyExchange()
    {
        return keyExchange;
    }

    /**
     * Encode this {@link KeyShareEntry} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint16(getNamedGroup(), output);
        TlsUtils.writeOpaque16(getKeyExchange(), output);
    }

    /**
     * Parse a {@link KeyShareEntry} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link KeyShareEntry} object.
     * @throws IOException
     */
    public static KeyShareEntry parse(InputStream input)
        throws IOException
    {
        int namedGroup = TlsUtils.readUint16(input);
        byte[] keyExchange = TlsUtils.readOpaque16(input, 1);
        return new KeyShareEntry(namedGroup, keyExchange);
    }
}
