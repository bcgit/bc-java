package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.io.Streams;

public final class Ed448PrivateKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed448.SECRET_KEY_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    public Ed448PrivateKeyParameters(SecureRandom random)
    {
        super(true);

        random.nextBytes(data);
    }

    public Ed448PrivateKeyParameters(byte[] buf, int off)
    {
        super(true);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public Ed448PrivateKeyParameters(InputStream input) throws IOException
    {
        super(true);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed448 private key");
        }
    }

    public void encode(byte[] buf, int off)
    {
        System.arraycopy(data, 0, buf, off, KEY_SIZE);
    }

    public Ed448PublicKeyParameters generatePublicKey()
    {
        byte[] publicKey = new byte[Ed448.PUBLIC_KEY_SIZE];
        Ed448.generatePublicKey(data, 0, publicKey, 0);
        return new Ed448PublicKeyParameters(publicKey, 0);
    }
}
