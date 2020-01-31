package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class Ed25519PrivateKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed25519.SECRET_KEY_SIZE;
    public static final int SIGNATURE_SIZE = Ed25519.SIGNATURE_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    private Ed25519PublicKeyParameters cachedPublicKey;

    public Ed25519PrivateKeyParameters(SecureRandom random)
    {
        super(true);

        Ed25519.generatePrivateKey(random, data);
    }

    public Ed25519PrivateKeyParameters(byte[] buf, int off)
    {
        super(true);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public Ed25519PrivateKeyParameters(InputStream input) throws IOException
    {
        super(true);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed25519 private key");
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

    public Ed25519PublicKeyParameters generatePublicKey()
    {
        synchronized (data)
        {
            if (null == cachedPublicKey)
            {
                byte[] publicKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
                Ed25519.generatePublicKey(data, 0, publicKey, 0);
                cachedPublicKey = new Ed25519PublicKeyParameters(publicKey, 0);
            }

            return cachedPublicKey;
        }
    }

    /**
     * @deprecated use overload that doesn't take a public key
     */
    public void sign(int algorithm, Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        sign(algorithm, ctx, msg, msgOff, msgLen, sig, sigOff);
    }

    public void sign(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        Ed25519PublicKeyParameters publicKey = generatePublicKey();

        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        publicKey.encode(pk, 0);

        switch (algorithm)
        {
        case Ed25519.Algorithm.Ed25519:
        {
            if (null != ctx)
            {
                throw new IllegalArgumentException("ctx");
            }

            Ed25519.sign(data, 0, pk, 0, msg, msgOff, msgLen, sig, sigOff);
            break;
        }
        case Ed25519.Algorithm.Ed25519ctx:
        {
            Ed25519.sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
            break;
        }
        case Ed25519.Algorithm.Ed25519ph:
        {
            if (Ed25519.PREHASH_SIZE != msgLen)
            {
                throw new IllegalArgumentException("msgLen");
            }

            Ed25519.signPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
            break;
        }
        default:
        {
            throw new IllegalArgumentException("algorithm");
        }
        }
    }
}
