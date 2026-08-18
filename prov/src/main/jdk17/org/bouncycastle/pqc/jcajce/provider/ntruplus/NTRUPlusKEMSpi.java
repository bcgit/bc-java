package org.bouncycastle.pqc.jcajce.provider.ntruplus;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;

/**
 * {@link javax.crypto.KEM} support for NTRU+, registered as {@code KEM.NTRUPLUS} plus one
 * parameter-set locked service per {@link NTRUPlusParameters} set, mirroring the family's existing
 * Cipher, KeyGenerator and KeyPairGenerator registrations.
 * <p>
 * All three sets produce a 256-bit session key. Note that the size fed to the spec validation comes
 * from NTRUPlusParameters.getSsBytes(), which is a fixed 32, while the bytes actually produced come
 * from the separate NTRUPlusEngine.SSBytes - so a parameter set with a different session key size
 * has to change both, or the validation will admit a no-KDF size the extractor cannot fill.
 */
public abstract class NTRUPlusKEMSpi
    implements KEMSpi
{
    private final NTRUPlusParameters ntruPlusParameters;

    NTRUPlusKEMSpi(NTRUPlusParameters ntruPlusParameters)
    {
        this.ntruPlusParameters = ntruPlusParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCNTRUPlusPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());

        return new NTRUPlusEncapsulatorSpi(bcPublicKey, resolveSpec(spec, bcPublicKey.getKeyParams()),
            secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCNTRUPlusPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());

        return new NTRUPlusDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, NTRUPlusKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        NTRUPlusParameters keyParameters = key.getParameters();

        // NTRU+ reports its shared secret in bytes, where the KEM spec is sized in bits
        return KdfUtil.resolveKemSpec(spec, "NTRU+", keyParameters.getName(),
            keyParameters.getSsBytes() * 8);
    }

    private void checkKeyParameters(NTRUPlusKeyParameters key) throws InvalidKeyException
    {
        if (ntruPlusParameters != null && ntruPlusParameters != key.getParameters())
        {
            throw new InvalidKeyException("NTRU+ key mismatch");
        }
    }

    public static class Base extends NTRUPlusKEMSpi
    {
        public Base()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class NTRUPlus768 extends NTRUPlusKEMSpi
    {
        public NTRUPlus768()
        {
            super(NTRUPlusParameters.ntruplus_kem_768);
        }
    }

    public static class NTRUPlus864 extends NTRUPlusKEMSpi
    {
        public NTRUPlus864()
        {
            super(NTRUPlusParameters.ntruplus_kem_864);
        }
    }

    public static class NTRUPlus1152 extends NTRUPlusKEMSpi
    {
        public NTRUPlus1152()
        {
            super(NTRUPlusParameters.ntruplus_kem_1152);
        }
    }
}
