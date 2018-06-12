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

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.MQVBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
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

    private final DHUnifiedAgreement unifiedAgreement;
    private final BasicAgreement mqvAgreement;

    private DHUParameterSpec dheParameters;
    private MQVParameterSpec mqvParameters;

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
        this.unifiedAgreement = null;
        this.mqvAgreement = null;
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        DHUnifiedAgreement unifiedAgreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
        this.unifiedAgreement = unifiedAgreement;
        this.mqvAgreement = null;
    }

    public KeyAgreementSpi(
        String kaAlgorithm,
        BasicAgreement mqvAgreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);
        this.unifiedAgreement = null;
        this.mqvAgreement = mqvAgreement;
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

        if (unifiedAgreement != null)
        {
            if (!lastPhase)
            {
                throw new IllegalStateException("unified Diffie-Hellman can use only two key pairs");
            }

            DHPublicKeyParameters staticKey = generatePublicKeyParameter((PublicKey)key);
            DHPublicKeyParameters ephemKey = generatePublicKeyParameter(dheParameters.getOtherPartyEphemeralKey());

            DHUPublicParameters pKey = new DHUPublicParameters(staticKey, ephemKey);

            result = unifiedAgreement.calculateAgreement(pKey);

            return null;
        }
        else if (mqvAgreement != null)
        {
            if (!lastPhase)
            {
                throw new IllegalStateException("MQV Diffie-Hellman can use only two key pairs");
            }

            DHPublicKeyParameters staticKey = generatePublicKeyParameter((PublicKey)key);
            DHPublicKeyParameters ephemKey = generatePublicKeyParameter(mqvParameters.getOtherPartyEphemeralKey());

            DHMQVPublicParameters pKey = new DHMQVPublicParameters(staticKey, ephemKey);

            result = bigIntToBytes(mqvAgreement.calculateAgreement(pKey));

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
                if (unifiedAgreement == null)
                {
                    throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
                }
                this.p = privKey.getParams().getP();
                this.g = privKey.getParams().getG();
                this.dheParameters = (DHUParameterSpec)params;
                this.ukmParameters = ((DHUParameterSpec)params).getUserKeyingMaterial();

                if (dheParameters.getEphemeralPublicKey() != null)
                {
                    unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey),
                        generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey()),
                        generatePublicKeyParameter(dheParameters.getEphemeralPublicKey())));
                }
                else
                {
                    unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey),
                            generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey())));
                }
            }
            else if (params instanceof MQVParameterSpec)
            {
                if (mqvAgreement == null)
                {
                    throw new InvalidAlgorithmParameterException("agreement algorithm not MQV based");
                }
                this.p = privKey.getParams().getP();
                this.g = privKey.getParams().getG();
                this.mqvParameters = (MQVParameterSpec)params;
                this.ukmParameters = ((MQVParameterSpec)params).getUserKeyingMaterial();

                if (mqvParameters.getEphemeralPublicKey() != null)
                {
                    mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(privKey),
                        generatePrivateKeyParameter(mqvParameters.getEphemeralPrivateKey()),
                        generatePublicKeyParameter(mqvParameters.getEphemeralPublicKey())));
                }
                else
                {
                    mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(privKey),
                            generatePrivateKeyParameter(mqvParameters.getEphemeralPrivateKey())));
                }
            }
            else if (params instanceof UserKeyingMaterialSpec)
            {
                if (kdf == null)
                {
                    throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
                }
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

                if (params instanceof DHDomainParameterSpec)
                {
                    return new DHPublicKeyParameters(pub.getY(), ((DHDomainParameterSpec)params).getDomainParameters());
                }
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

    public static class DHwithSHA1KDF
        extends KeyAgreementSpi
    {
        public DHwithSHA1KDF()
        {
            super("DHwithSHA1CKDF", new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class DHwithSHA224KDF
        extends KeyAgreementSpi
    {
        public DHwithSHA224KDF()
        {
            super("DHwithSHA224CKDF", new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class DHwithSHA256KDF
        extends KeyAgreementSpi
    {
        public DHwithSHA256KDF()
        {
            super("DHwithSHA256CKDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class DHwithSHA384KDF
        extends KeyAgreementSpi
    {
        public DHwithSHA384KDF()
        {
            super("DHwithSHA384KDF", new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class DHwithSHA512KDF
        extends KeyAgreementSpi
    {
        public DHwithSHA512KDF()
        {
            super("DHwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    public static class DHwithSHA1CKDF
        extends KeyAgreementSpi
    {
        public DHwithSHA1CKDF()
        {
            super("DHwithSHA1CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class DHwithSHA224CKDF
        extends KeyAgreementSpi
    {
        public DHwithSHA224CKDF()
        {
            super("DHwithSHA224CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class DHwithSHA256CKDF
        extends KeyAgreementSpi
    {
        public DHwithSHA256CKDF()
        {
            super("DHwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class DHwithSHA384CKDF
        extends KeyAgreementSpi
    {
        public DHwithSHA384CKDF()
        {
            super("DHwithSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class DHwithSHA512CKDF
        extends KeyAgreementSpi
    {
        public DHwithSHA512CKDF()
        {
            super("DHwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    public static class DHUwithSHA1KDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA1KDF()
        {
            super("DHUwithSHA1KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class DHUwithSHA224KDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA224KDF()
        {
            super("DHUwithSHA224KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class DHUwithSHA256KDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA256KDF()
        {
            super("DHUwithSHA256KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class DHUwithSHA384KDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA384KDF()
        {
            super("DHUwithSHA384KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class DHUwithSHA512KDF
        extends KeyAgreementSpi
    {
        public DHUwithSHA512KDF()
        {
            super("DHUwithSHA512KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
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

    public static class MQVwithSHA1KDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA1KDF()
        {
            super("MQVwithSHA1KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class MQVwithSHA224KDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA224KDF()
        {
            super("MQVwithSHA224KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class MQVwithSHA256KDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA256KDF()
        {
            super("MQVwithSHA256KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class MQVwithSHA384KDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA384KDF()
        {
            super("MQVwithSHA384KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class MQVwithSHA512KDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA512KDF()
        {
            super("MQVwithSHA512KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    public static class MQVwithSHA1CKDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA1CKDF()
        {
            super("MQVwithSHA1CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    public static class MQVwithSHA224CKDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA224CKDF()
        {
            super("MQVwithSHA224CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    public static class MQVwithSHA256CKDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA256CKDF()
        {
            super("MQVwithSHA256CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class MQVwithSHA384CKDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA384CKDF()
        {
            super("MQVwithSHA384CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class MQVwithSHA512CKDF
        extends KeyAgreementSpi
    {
        public MQVwithSHA512CKDF()
        {
            super("MQVwithSHA512CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }
}
