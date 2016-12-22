package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

/**
 * Diffie-Hellman key agreement. There's actually a better way of doing this
 * if you are using long term public keys, see the light-weight version for
 * details.
 */
public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private BigInteger      x;
    private BigInteger      p;
    private BigInteger      g;

    private BigInteger     result;

    public KeyAgreementSpi()
    {
        super("Diffie-Hellman", null);
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
    }

    protected byte[] bigIntToBytes(
        BigInteger    r)
    {
        //
        // RFC 2631 (2.1.2) specifies that the secret should be padded with leading zeros if necessary
        // must be the same length as p
        //
        int expectedLength = (p.bitLength() + 7) / 8;

        byte[]    tmp = r.toByteArray();

        if (tmp.length == expectedLength)
        {
            return tmp;
        }

        if (tmp[0] == 0 && tmp.length == expectedLength + 1)
        {
            byte[]    rv = new byte[tmp.length - 1];
            
            System.arraycopy(tmp, 1, rv, 0, rv.length);
            return rv;
        }

        // tmp must be shorter than expectedLength
        // pad to the left with zeros.
        byte[]    rv = new byte[expectedLength];

        System.arraycopy(tmp, 0, rv, rv.length - tmp.length, tmp.length);

        return rv;
    }
    
    protected Key engineDoPhase(
        Key     key,
        boolean lastPhase) 
        throws InvalidKeyException, IllegalStateException
    {
        if (x == null)
        {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }

        if (!(key instanceof DHPublicKey))
        {
            throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey");
        }
        DHPublicKey pubKey = (DHPublicKey)key;

        if (!pubKey.getParams().getG().equals(g) || !pubKey.getParams().getP().equals(p))
        {
            throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
        }

        BigInteger peerY = ((DHPublicKey)key).getY();
        if (peerY == null || peerY.compareTo(TWO) < 0
            || peerY.compareTo(p.subtract(ONE)) >= 0)
        {
            throw new InvalidKeyException("Invalid DH PublicKey");
        }

        result = peerY.modPow(x, p);
        if (result.compareTo(ONE) == 0)
        {
            throw new InvalidKeyException("Shared key can't be 1");
        }

        if (lastPhase)
        {
            return null;
        }

        return new BCDHPublicKey(result, pubKey.getParams());
    }

    protected byte[] engineGenerateSecret() 
        throws IllegalStateException
    {
        if (x == null)
        {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }

        return super.engineGenerateSecret();
    }

    protected int engineGenerateSecret(
        byte[]  sharedSecret,
        int     offset) 
        throws IllegalStateException, ShortBufferException
    {
        if (x == null)
        {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }

        return super.engineGenerateSecret(sharedSecret, offset);
    }

    protected SecretKey engineGenerateSecret(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        if (x == null)
        {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }

        byte[] res = bigIntToBytes(result);

        // for JSSE compatibility
        if (algorithm.equals("TlsPremasterSecret"))
        {
            return new SecretKeySpec(trimZeroes(res), algorithm);
        }

        return super.engineGenerateSecret(algorithm);
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random) 
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(key instanceof DHPrivateKey))
        {
            throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation");
        }
        DHPrivateKey    privKey = (DHPrivateKey)key;

        if (params != null)
        {
            if (params instanceof DHParameterSpec)    // p, g override.
            {
                DHParameterSpec p = (DHParameterSpec)params;

                this.p = p.getP();
                this.g = p.getG();
            }
            else if (params instanceof UserKeyingMaterialSpec)
            {
                this.p = privKey.getParams().getP();
                this.g = privKey.getParams().getG();
                this.ukmParameters = ((UserKeyingMaterialSpec)params).getUserKeyingMaterial();
            }
            else
            {
                throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
            }
        }
        else
        {
            this.p = privKey.getParams().getP();
            this.g = privKey.getParams().getG();
        }

        this.x = this.result = privKey.getX();
    }

    protected void engineInit(
        Key             key,
        SecureRandom    random) 
        throws InvalidKeyException
    {
        if (!(key instanceof DHPrivateKey))
        {
            throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey");
        }

        DHPrivateKey    privKey = (DHPrivateKey)key;

        this.p = privKey.getParams().getP();
        this.g = privKey.getParams().getG();
        this.x = this.result = privKey.getX();
    }

    protected byte[] calcSecret()
    {
        return bigIntToBytes(result);
    }

    public static class DHwithRFC2631KDF
        extends KeyAgreementSpi
    {
        public DHwithRFC2631KDF()
        {
            super("DHwithRFC2631KDF", new DHKEKGenerator(DigestFactory.createSHA1()));
        }
    }
}
