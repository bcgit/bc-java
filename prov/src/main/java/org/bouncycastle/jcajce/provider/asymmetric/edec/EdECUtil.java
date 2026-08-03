package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * utility class for converting jce/jca XDH, and EdDSA
 * objects into their org.bouncycastle.crypto counterparts.
 * <p>
 * NOTE: this class is shared by every JDK version of the multi-release jar and must not be
 * MR-overlaid - the version-specific key handling lives in {@link XDHKeys} (jdk1.11 twin) and
 * {@link EdDSAKeys} (jdk1.15 twin), which call back into the helpers here.
 */
class EdECUtil
{
    public static AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPublicKey)
        {
            return ((BCXDHPublicKey)key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPublicKey)
        {
            return ((BCEdDSAPublicKey)key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH public key");
                }

                return PublicKeyFactory.createKey(bytes);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH public key: " + e.getMessage());
            }
        }
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            return ((BCXDHPrivateKey)key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPrivateKey)
        {
            return ((BCEdDSAPrivateKey)key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH private key");
                }

                return PrivateKeyFactory.createKey(bytes);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH private key: " + e.getMessage());
            }
        }
    }

    static X25519PrivateKeyParameters getX25519PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (X25519PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use XEC private key (X25519) with scalar of incorrect length");
        }

        return new X25519PrivateKeyParameters(keyData, 0);
    }

    static X448PrivateKeyParameters getX448PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (X448PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use XEC private key (X448) with scalar of incorrect length");
        }

        return new X448PrivateKeyParameters(keyData, 0);
    }

    static X25519PublicKeyParameters getX25519PublicKey(BigInteger u)
        throws InvalidKeyException
    {
        return new X25519PublicKeyParameters(getXDHPublicKeyData(X25519PublicKeyParameters.KEY_SIZE, u), 0);
    }

    static X448PublicKeyParameters getX448PublicKey(BigInteger u)
        throws InvalidKeyException
    {
        return new X448PublicKeyParameters(getXDHPublicKeyData(X448PublicKeyParameters.KEY_SIZE, u), 0);
    }

    private static byte[] getXDHPublicKeyData(int length, BigInteger u)
        throws InvalidKeyException
    {
        try
        {
            return Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(length, u));
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException("cannot use XEC public key with invalid U value");
        }
    }

    static Ed25519PrivateKeyParameters getEd25519PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (Ed25519PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use EdEC private key (Ed25519) with bytes of incorrect length");
        }

        return new Ed25519PrivateKeyParameters(keyData, 0);
    }

    static Ed448PrivateKeyParameters getEd448PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (Ed448PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use EdEC private key (Ed448) with bytes of incorrect length");
        }

        return new Ed448PrivateKeyParameters(keyData, 0);
    }

    static Ed25519PublicKeyParameters getEd25519PublicKey(BigInteger y, boolean xOdd)
        throws InvalidKeyException
    {
        return new Ed25519PublicKeyParameters(getEdDSAPublicKeyData(Ed25519PublicKeyParameters.KEY_SIZE, y, xOdd), 0);
    }

    static Ed448PublicKeyParameters getEd448PublicKey(BigInteger y, boolean xOdd)
        throws InvalidKeyException
    {
        return new Ed448PublicKeyParameters(getEdDSAPublicKeyData(Ed448PublicKeyParameters.KEY_SIZE, y, xOdd), 0);
    }

    private static byte[] getEdDSAPublicKeyData(int length, BigInteger y, boolean xOdd)
        throws InvalidKeyException
    {
        if (y.signum() < 0)
        {
            throw new InvalidKeyException("cannot use EdEC public key with negative Y value");
        }

        try
        {
            byte[] keyData = BigIntegers.asUnsignedByteArray(length, y);
            if ((keyData[0] & 0x80) == 0)
            {
                if (xOdd)
                {
                    keyData[0] |= 0x80;
                }

                return Arrays.reverseInPlace(keyData);
            }
        }
        catch (RuntimeException e)
        {
        }

        throw new InvalidKeyException("cannot use EdEC public key with invalid Y value");
    }
}
