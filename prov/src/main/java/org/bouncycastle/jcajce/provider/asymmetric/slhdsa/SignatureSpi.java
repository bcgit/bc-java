package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

public class SignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    private final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    private final SLHDSASigner signer;
    private final SLHDSAParameters parameters;

    protected SignatureSpi(SLHDSASigner signer)
    {
        super("SLH-DSA");

        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(SLHDSASigner signer, SLHDSAParameters parameters)
    {
        super(SLHDSAParameterSpec.fromName(parameters.getName()).getName());

        this.signer = signer;
        this.parameters = parameters;
    }

    protected void verifyInit(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCSLHDSAPublicKey)
        {
            BCSLHDSAPublicKey key = (BCSLHDSAPublicKey)publicKey;

            this.keyParams = key.getKeyParams();

            HashSignatureSpi.checkKeyParameters(parameters, null, key.getKeyParams().getParameters());
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to SLH-DSA");
        }
    }

    protected void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.appRandom = random;
        if (privateKey instanceof BCSLHDSAPrivateKey)
        {
            BCSLHDSAPrivateKey key = (BCSLHDSAPrivateKey)privateKey;

            this.keyParams = key.getKeyParams();

            HashSignatureSpi.checkKeyParameters(parameters, null, key.getKeyParams().getParameters());
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to SLH-DSA");
        }
    }

    protected void updateEngine(byte b)
        throws SignatureException
    {
        bOut.write(b);
    }

    protected void updateEngine(byte[] buf, int off, int len)
        throws SignatureException
    {
        bOut.write(buf, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        CipherParameters param = keyParams;

        if (!(param instanceof SLHDSAPrivateKeyParameters))
        {
            throw new SignatureException("engine initialized for verification");
        }

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
            this.isInitState = true;
            bOut.reset();
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        CipherParameters param = keyParams;

        if (!(param instanceof SLHDSAPublicKeyParameters))
        {
            throw new SignatureException("engine initialized for signing");
        }

        try
        {
            return signer.verifySignature(bOut.toByteArray(), sigBytes);
        }
        finally
        {
            this.isInitState = true;
            bOut.reset();
        }
    }

    protected void reInitialize(boolean forSigning, CipherParameters params)
    {
        signer.init(forSigning, params);

        bOut.reset();
    }

    public static class Direct
        extends SignatureSpi
    {
        public Direct()
        {
            super(new SLHDSASigner());
        }
    }

    public static class Sha2_128s
        extends SignatureSpi
    {
        public Sha2_128s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_128s);
        }
    }

    public static class Sha2_128f
        extends SignatureSpi
    {
        public Sha2_128f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_128f);
        }
    }

    public static class Sha2_192s
        extends SignatureSpi
    {
        public Sha2_192s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_192s);
        }
    }

    public static class Sha2_192f
        extends SignatureSpi
    {
        public Sha2_192f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_192f);
        }
    }

    public static class Sha2_256s
        extends SignatureSpi
    {
        public Sha2_256s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_256s);
        }
    }

    public static class Sha2_256f
        extends SignatureSpi
    {
        public Sha2_256f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.sha2_256f);
        }
    }

    public static class Shake_128s
        extends SignatureSpi
    {
        public Shake_128s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_128s);
        }
    }

    public static class Shake_128f
        extends SignatureSpi
    {
        public Shake_128f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_128f);
        }
    }

    public static class Shake_192s
        extends SignatureSpi
    {
        public Shake_192s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_192s);
        }
    }

    public static class Shake_192f
        extends SignatureSpi
    {
        public Shake_192f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_192f);
        }
    }

    public static class Shake_256s
        extends SignatureSpi
    {
        public Shake_256s()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_256s);
        }
    }

    public static class Shake_256f
        extends SignatureSpi
    {
        public Shake_256f()
        {
            super(new SLHDSASigner(), SLHDSAParameters.shake_256f);
        }
    }
}
