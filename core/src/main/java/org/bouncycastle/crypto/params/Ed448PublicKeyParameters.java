package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.io.Streams;

public final class Ed448PublicKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed448.PUBLIC_KEY_SIZE;

    private final Ed448.PublicPoint publicPoint;

    public Ed448PublicKeyParameters(byte[] buf)
    {
        this(validate(buf), 0);
    }

    public Ed448PublicKeyParameters(byte[] buf, int off)
    {
        super(false);

        this.publicPoint = parse(buf, off);
    }

    public Ed448PublicKeyParameters(InputStream input) throws IOException
    {
        super(false);

        byte[] data = new byte[KEY_SIZE];

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed448 public key");
        }

        this.publicPoint = parse(data, 0);
    }

    public Ed448PublicKeyParameters(Ed448.PublicPoint publicPoint)
    {
        super(false);

        if (publicPoint == null)
        {
            throw new NullPointerException("'publicPoint' cannot be null");
        }

        this.publicPoint = publicPoint;
    }

    public void encode(byte[] buf, int off)
    {
        Ed448.encodePublicPoint(publicPoint, buf, off);
    }

    public byte[] getEncoded()
    {
        byte[] data = new byte[KEY_SIZE];
        encode(data, 0);
        return data;
    }

    public boolean verify(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        switch (algorithm)
        {
        case Ed448.Algorithm.Ed448:
        {
            if (null == ctx)
            {
                throw new NullPointerException("'ctx' cannot be null");
            }
            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("ctx");
            }

            return Ed448.verify(sig, sigOff, publicPoint, ctx, msg, msgOff, msgLen);
        }
        case Ed448.Algorithm.Ed448ph:
        {
            if (null == ctx)
            {
                throw new NullPointerException("'ctx' cannot be null");
            }
            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("ctx");
            }
            if (Ed448.PREHASH_SIZE != msgLen)
            {
                throw new IllegalArgumentException("msgLen");
            }

            return Ed448.verifyPrehash(sig, sigOff, publicPoint, ctx, msg, msgOff);
        }
        default:
        {
            throw new IllegalArgumentException("algorithm");
        }
        }
    }

    private static Ed448.PublicPoint parse(byte[] buf, int off)
    {
        Ed448.PublicPoint publicPoint = Ed448.validatePublicKeyPartialExport(buf, off);
        if (publicPoint == null)
        {
            throw new IllegalArgumentException("invalid public key");
        }
        return publicPoint;
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
