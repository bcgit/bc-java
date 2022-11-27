package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.io.Streams;

public final class Ed25519PublicKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed25519.PUBLIC_KEY_SIZE;

    private final Ed25519.PublicPoint publicPoint;

    public Ed25519PublicKeyParameters(byte[] buf)
    {
        this(validate(buf), 0);
    }

    public Ed25519PublicKeyParameters(byte[] buf, int off)
    {
        super(false);

        this.publicPoint = parse(buf, off);
    }

    public Ed25519PublicKeyParameters(InputStream input) throws IOException
    {
        super(false);

        byte[] data = new byte[KEY_SIZE];

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed25519 public key");
        }

        this.publicPoint = parse(data, 0);
    }

    public Ed25519PublicKeyParameters(Ed25519.PublicPoint publicPoint)
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
        Ed25519.encodePublicPoint(publicPoint, buf, off);
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
        case Ed25519.Algorithm.Ed25519:
        {
            if (null != ctx)
            {
                throw new IllegalArgumentException("ctx");
            }

            return Ed25519.verify(sig, sigOff, publicPoint, msg, msgOff, msgLen);
        }
        case Ed25519.Algorithm.Ed25519ctx:
        {
            if (null == ctx)
            {
                throw new NullPointerException("'ctx' cannot be null");
            }
            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("ctx");
            }

            return Ed25519.verify(sig, sigOff, publicPoint, ctx, msg, msgOff, msgLen);
        }
        case Ed25519.Algorithm.Ed25519ph:
        {
            if (null == ctx)
            {
                throw new NullPointerException("'ctx' cannot be null");
            }
            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("ctx");
            }
            if (Ed25519.PREHASH_SIZE != msgLen)
            {
                throw new IllegalArgumentException("msgLen");
            }

            return Ed25519.verifyPrehash(sig, sigOff, publicPoint, ctx, msg, msgOff);
        }
        default:
        {
            throw new IllegalArgumentException("algorithm");
        }
        }
    }

    private static Ed25519.PublicPoint parse(byte[] buf, int off)
    {
        Ed25519.PublicPoint publicPoint = Ed25519.validatePublicKeyPartialExport(buf, off);
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
