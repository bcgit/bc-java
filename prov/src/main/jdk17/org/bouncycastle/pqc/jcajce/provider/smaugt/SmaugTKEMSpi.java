package org.bouncycastle.pqc.jcajce.provider.smaugt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;

/**
 * {@link javax.crypto.KEM} support for SMAUG-T, registered as {@code KEM.SMAUGT} plus one
 * parameter-set locked service per {@link SmaugTParameters} set, mirroring the family's existing
 * Cipher, KeyGenerator and KeyPairGenerator registrations.
 * <p>
 * All four sets produce a 256-bit session key, but the size is taken from the key's own parameters
 * rather than assumed, so a future set with a different one needs no change here.
 */
public abstract class SmaugTKEMSpi
    implements KEMSpi
{
    private final SmaugTParameters smaugTParameters;

    SmaugTKEMSpi(SmaugTParameters smaugTParameters)
    {
        this.smaugTParameters = smaugTParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCSmaugTPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());

        return new SmaugTEncapsulatorSpi(bcPublicKey, resolveSpec(spec, bcPublicKey.getKeyParams()),
            secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCSmaugTPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());

        return new SmaugTDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, SmaugTKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        SmaugTParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "SMAUG-T", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(SmaugTKeyParameters key) throws InvalidKeyException
    {
        if (smaugTParameters != null && smaugTParameters != key.getParameters())
        {
            throw new InvalidKeyException("SMAUG-T key mismatch");
        }
    }

    public static class Base extends SmaugTKEMSpi
    {
        public Base()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class Mode1 extends SmaugTKEMSpi
    {
        public Mode1()
        {
            super(SmaugTParameters.smaugt_mode1);
        }
    }

    public static class Mode3 extends SmaugTKEMSpi
    {
        public Mode3()
        {
            super(SmaugTParameters.smaugt_mode3);
        }
    }

    public static class Mode5 extends SmaugTKEMSpi
    {
        public Mode5()
        {
            super(SmaugTParameters.smaugt_mode5);
        }
    }

    public static class ModeT extends SmaugTKEMSpi
    {
        public ModeT()
        {
            super(SmaugTParameters.smaugt_modet);
        }
    }
}
