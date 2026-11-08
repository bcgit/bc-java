package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class X25519PrivateKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = X25519.SCALAR_SIZE;
    public static final int SECRET_SIZE = X25519.POINT_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    public X25519PrivateKeyParameters(SecureRandom random)
    {
        super(true);

        X25519.generatePrivateKey(random, data);
    }

    public X25519PrivateKeyParameters(byte[] buf)
    {
        this(validate(buf), 0);
    }

    public X25519PrivateKeyParameters(byte[] buf, int off)
    {
        super(true);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public X25519PrivateKeyParameters(InputStream input) throws IOException
    {
        super(true);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of X25519 private key");
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

    public X25519PublicKeyParameters generatePublicKey()
    {
        byte[] publicKey = new byte[X25519.POINT_SIZE];
        X25519.generatePublicKey(data, 0, publicKey, 0);
        return new X25519PublicKeyParameters(publicKey, 0);
    }

    public void generateSecret(X25519PublicKeyParameters publicKey, byte[] buf, int off)
    {
        byte[] encoded = new byte[X25519.POINT_SIZE];
        publicKey.encode(encoded, 0);

        // computed aside and copied out only once checked, so a failed agreement leaves buf as it was rather than
        // holding the all-zero result
        byte[] secret = new byte[X25519.POINT_SIZE];
        try
        {
            if (!X25519.calculateAgreement(data, 0, encoded, 0, secret, 0))
            {
                throw new IllegalStateException("X25519 agreement failed");
            }

            System.arraycopy(secret, 0, buf, off, X25519.POINT_SIZE);
        }
        finally
        {
            Arrays.clear(secret);
        }
    }

    private static byte[] validate(byte[] buf)
    {
        if (buf.length != KEY_SIZE)
        {
            throw new IllegalArgumentException("'buf' must have length " + KEY_SIZE);
        }
        return buf;
    }
}
