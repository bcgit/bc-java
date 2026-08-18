package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.params.FrodoKEMKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * {@link javax.crypto.KEM} support for FrodoKEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026,
 * Clause 14, registered as {@code KEM.FRODOKEM} plus one parameter-set locked service per
 * {@link FrodoKEMParameters} set.
 * <p>
 * With a null spec the shared secret is the mechanism's own session key - the interoperable form.
 * Note its size varies with the parameter set: 24 bytes for the 976 sets, 32 bytes for the 1344
 * sets. A {@link KTSParameterSpec} KDF may optionally be layered on top for generic use.
 */
public abstract class FrodoKEMSpi
    implements KEMSpi
{
    private final FrodoKEMParameters frodoKEMParameters;

    FrodoKEMSpi(FrodoKEMParameters frodoKEMParameters)
    {
        this.frodoKEMParameters = frodoKEMParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCFrodoKEMPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());

        return new FrodoKEMEncapsulatorSpi(bcPublicKey, resolveSpec(spec, bcPublicKey.getKeyParams()),
            secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCFrodoKEMPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());

        return new FrodoKEMDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    /**
     * Unlike ML-KEM, the FrodoKEM session key size varies with the parameter set - 192 bits for the
     * 976 sets, 256 for the 1344 sets - so the default spec and the satisfiability of a KDF-less
     * one both have to be taken from the key's own parameters rather than assumed to be 256.
     */
    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, FrodoKEMKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        FrodoKEMParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "FrodoKEM", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(FrodoKEMKeyParameters key) throws InvalidKeyException
    {
        if (frodoKEMParameters != null && frodoKEMParameters != key.getParameters())
        {
            throw new InvalidKeyException("FrodoKEM key mismatch");
        }
    }

    public static class Base extends FrodoKEMSpi
    {
        public Base()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class Frodokem976Shake extends FrodoKEMSpi
    {
        public Frodokem976Shake()
        {
            super(FrodoKEMParameters.frodokem976shake);
        }
    }

    public static class Frodokem1344Shake extends FrodoKEMSpi
    {
        public Frodokem1344Shake()
        {
            super(FrodoKEMParameters.frodokem1344shake);
        }
    }

    public static class EFrodokem976Shake extends FrodoKEMSpi
    {
        public EFrodokem976Shake()
        {
            super(FrodoKEMParameters.efrodokem976shake);
        }
    }

    public static class EFrodokem1344Shake extends FrodoKEMSpi
    {
        public EFrodokem1344Shake()
        {
            super(FrodoKEMParameters.efrodokem1344shake);
        }
    }

    public static class Frodokem976Aes extends FrodoKEMSpi
    {
        public Frodokem976Aes()
        {
            super(FrodoKEMParameters.frodokem976aes);
        }
    }

    public static class Frodokem1344Aes extends FrodoKEMSpi
    {
        public Frodokem1344Aes()
        {
            super(FrodoKEMParameters.frodokem1344aes);
        }
    }

    public static class EFrodokem976Aes extends FrodoKEMSpi
    {
        public EFrodokem976Aes()
        {
            super(FrodoKEMParameters.efrodokem976aes);
        }
    }

    public static class EFrodokem1344Aes extends FrodoKEMSpi
    {
        public EFrodokem1344Aes()
        {
            super(FrodoKEMParameters.efrodokem1344aes);
        }
    }
}
