package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class X448PublicKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = X448.POINT_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    public X448PublicKeyParameters(byte[] buf, int off)
    {
        super(false);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public X448PublicKeyParameters(InputStream input) throws IOException
    {
        super(false);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of X448 public key");
        }
    }

    public void encode(byte[] buf, int off)
    {
        System.arraycopy(data, 0, buf, off, KEY_SIZE);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(data);
    }
}
