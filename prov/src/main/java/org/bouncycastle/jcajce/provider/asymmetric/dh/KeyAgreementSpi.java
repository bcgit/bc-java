package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
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

    private final DHUnifiedAgreement agreement;

    private DHUParameterSpec dheParameters;

    private BigInteger      x;
    private BigInteger      p;
    private BigInteger      g;

    private byte[]          result;

    public KeyAgreementSpi()
    {
        this("Diffie-Hellman", null);
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
        this.agreement = null;
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        DHUnifiedAgreement agreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
        this.agreement = agreement;
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

        if (agreement != null)
        {
            if (!lastPhase)
            {
                throw new IllegalStateException("unified Diffie-Hellman can use only two key pairs");
            }

            DHPublicKeyParameters staticKey = generatePublicKeyParameter((PublicKey)key);
            DHPublicKeyParameters ephemKey = generatePublicKeyParameter(dheParameters.getOtherPartyEphemeralKey());

            DHUPublicParameters pKey = new DHUPublicParameters(staticKey, ephemKey);

            result = agreement.calculateAgreement(pKey);

            return null;
        }
        else
        {
            BigInteger res = peerY.modPow(x, p);
            if (res.compareTo(ONE) == 0)
            {
                throw new InvalidKeyException("Shared key can't be 1");
            }

            result = bigIntToBytes(res);

            if (lastPhase)
            {
                return null;
            }

            return new BCDHPublicKey(res, pubKey.getParams());
        }
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

        // for JSSE compatibility
        if (algorithm.equals("TlsPremasterSecret"))
        {
            return new SecretKeySpec(trimZeroes(result), algorithm);
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
                this.dheParameters = null;
                this.ukmParameters = null;
            }
            else if (params instanceof DHUParameterSpec)
            {
                this.p = privKey.getParams().getP();
                this.g = privKey.getParams().getG();
                this.dheParameters = (DHUParameterSpec)params;
                this.ukmParameters = ((DHUParameterSpec)params).getUserKeyingMaterial();

                if (dheParameters.getEphemeralPublicKey() != null)
                {
                    agreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey),
                        generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey()),
                        generatePublicKeyParameter(dheParameters.getEphemeralPublicKey())));
                }
                else
                {
                    agreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey),
                            generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey())));
                }
            }
            else if (params instanceof UserKeyingMaterialSpec)
            {
                this.p = privKey.getParams().getP();
                this.g = privKey.getParams().getG();
                this.dheParameters = null;
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

        this.x = privKey.getX();
        this.result = bigIntToBytes(x);
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
        this.x = privKey.getX();
        this.result = bigIntToBytes(x);
    }

    protected byte[] calcSecret()
    {
        return result;
    }

    private DHPrivateKeyParameters generatePrivateKeyParameter(PrivateKey privKey)
        throws InvalidKeyException
    {
        if (privKey instanceof DHPrivateKey)
        {
            if (privKey instanceof BCDHPrivateKey)
            {
                return ((BCDHPrivateKey)privKey).engineGetKeyParameters();
            }
            else
            {
                DHPrivateKey pub = (DHPrivateKey)privKey;

                DHParameterSpec params = pub.getParams();
                return new DHPrivateKeyParameters(pub.getX(),
                            new DHParameters(params.getP(), params.getG(), null, params.getL()));
            }
        }
        else
        {
            throw new InvalidKeyException("private key not a DHPrivateKey");
        }
    }

    private DHPublicKeyParameters generatePublicKeyParameter(PublicKey pubKey)
        throws InvalidKeyException
    {
        if (pubKey instanceof DHPublicKey)
        {
            if (pubKey instanceof BCDHPublicKey)
            {
                return ((BCDHPublicKey)pubKey).engineGetKeyParameters();
            }
            else
            {
                DHPublicKey pub = (DHPublicKey)pubKey;

                DHParameterSpec params = pub.getParams();
                return new DHPublicKeyParameters(pub.getY(),
                            new DHParameters(params.getP(), params.getG(), null, params.getL()));
            }
        }
        else
        {
            throw new InvalidKeyException("public key not a DHPublicKey");
        }
    }

    public static class DHwithRFC2631KDF
        extends KeyAgreementSpi
    {
        public DHwithRFC2631KDF()
        {
            super("DHwithRFC2631KDF", new DHKEKGenerator(DigestFactory.createSHA1()));
        }
    }


    public static class DHUwithSHA1CKDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA1CKDF()
        {
            super("DHUwithSHA1CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class DHUwithSHA224CKDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA224CKDF()
        {
            super("DHUwithSHA224CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class DHUwithSHA256CKDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA256CKDF()
        {
            super("DHUwithSHA256CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class DHUwithSHA384CKDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA384CKDF()
        {
            super("DHUwithSHA384CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class DHUwithSHA512CKDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA512CKDF()
        {
            super("DHUwithSHA512CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }
}
