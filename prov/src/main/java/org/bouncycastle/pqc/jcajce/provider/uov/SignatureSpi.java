package org.bouncycastle.pqc.jcajce.provider.uov;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.uov.UOVParameters;
import org.bouncycastle.pqc.crypto.uov.UOVSigner;
import org.bouncycastle.util.Strings;

/**
 * JCA SignatureSpi for UOV. Buffers the message bytes through
 * engineUpdate then dispatches to the one-shot UOVSigner. Per-variant
 * subclasses lock the SPI to a specific UOVParameters set; the generic SPI
 * accepts whatever variant the supplied key carries.
 */
public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final UOVSigner signer;
    private final UOVParameters parameters;
    private SecureRandom random;

    protected SignatureSpi(UOVSigner signer)
    {
        super("UOV");
        this.signer = signer;
        this.parameters = null;
        this.bOut = new ByteArrayOutputStream();
    }

    protected SignatureSpi(UOVSigner signer, UOVParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.signer = signer;
        this.parameters = parameters;
        this.bOut = new ByteArrayOutputStream();
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
    {
        if (!(publicKey instanceof BCUOVPublicKey))
        {
            try
            {
                publicKey = new BCUOVPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to UOV: " + e.getMessage());
            }
        }
        BCUOVPublicKey key = (BCUOVPublicKey) publicKey;
        if (parameters != null)
        {
            String canonical = Strings.toUpperCase(parameters.getName());
            if (!canonical.equals(key.getAlgorithm()))
            {
                throw new InvalidKeyException("signature configured for " + canonical);
            }
        }
        signer.init(false, key.getKeyParams());
        bOut.reset();
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException
    {
        if (!(privateKey instanceof BCUOVPrivateKey))
        {
            throw new InvalidKeyException("unknown private key passed to UOV");
        }
        BCUOVPrivateKey key = (BCUOVPrivateKey) privateKey;
        if (parameters != null)
        {
            String canonical = Strings.toUpperCase(parameters.getName());
            if (!canonical.equals(key.getAlgorithm()))
            {
                throw new InvalidKeyException("signature configured for " + canonical);
            }
        }
        CipherParameters param = key.getKeyParams();
        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }
        signer.init(true, param);
        bOut.reset();
    }

    protected void engineUpdate(byte b)
            throws SignatureException
    {
        bOut.write(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
            throws SignatureException
    {
        bOut.write(bytes, off, len);
    }

    protected byte[] engineSign()
            throws SignatureException
    {
        try
        {
            byte[] sig = signer.generateSignature(bOut.toByteArray());
            return sig;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
        finally
        {
            bOut.reset();
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
    {
        try
        {
            return signer.verifySignature(bOut.toByteArray(), sigBytes);
        }
        finally
        {
            bOut.reset();
        }
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with {@link #engineSetParameter(AlgorithmParameterSpec)}.
     */
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("setParameter unsupported");
    }

    /**
     * @deprecated replaced with {@link #engineGetParameters()}.
     */
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("getParameter unsupported");
    }

    public static class Generic extends SignatureSpi
    {
        public Generic()
        {
            super(new UOVSigner());
        }
    }

    public static class Is extends SignatureSpi
    {
        public Is()
        {
            super(new UOVSigner(), UOVParameters.uov_Is);
        }
    }

    public static class IsPkc extends SignatureSpi
    {
        public IsPkc()
        {
            super(new UOVSigner(), UOVParameters.uov_Is_pkc);
        }
    }

    public static class IsPkcSkc extends SignatureSpi
    {
        public IsPkcSkc()
        {
            super(new UOVSigner(), UOVParameters.uov_Is_pkc_skc);
        }
    }

    public static class Ip extends SignatureSpi
    {
        public Ip()
        {
            super(new UOVSigner(), UOVParameters.uov_Ip);
        }
    }

    public static class IpPkc extends SignatureSpi
    {
        public IpPkc()
        {
            super(new UOVSigner(), UOVParameters.uov_Ip_pkc);
        }
    }

    public static class IpPkcSkc extends SignatureSpi
    {
        public IpPkcSkc()
        {
            super(new UOVSigner(), UOVParameters.uov_Ip_pkc_skc);
        }
    }

    public static class III extends SignatureSpi
    {
        public III()
        {
            super(new UOVSigner(), UOVParameters.uov_III);
        }
    }

    public static class IIIPkc extends SignatureSpi
    {
        public IIIPkc()
        {
            super(new UOVSigner(), UOVParameters.uov_III_pkc);
        }
    }

    public static class IIIPkcSkc extends SignatureSpi
    {
        public IIIPkcSkc()
        {
            super(new UOVSigner(), UOVParameters.uov_III_pkc_skc);
        }
    }

    public static class V extends SignatureSpi
    {
        public V()
        {
            super(new UOVSigner(), UOVParameters.uov_V);
        }
    }

    public static class VPkc extends SignatureSpi
    {
        public VPkc()
        {
            super(new UOVSigner(), UOVParameters.uov_V_pkc);
        }
    }

    public static class VPkcSkc extends SignatureSpi
    {
        public VPkcSkc()
        {
            super(new UOVSigner(), UOVParameters.uov_V_pkc_skc);
        }
    }
}
