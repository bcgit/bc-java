package org.bouncycastle.pqc.jcajce.provider.ntru;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;

public abstract class NTRUKEMSpi
    implements KEMSpi
{
    private final NTRUParameters ntruParameters;

    NTRUKEMSpi(NTRUParameters ntruParameters)
    {
        this.ntruParameters = ntruParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCNTRUPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());


        return new NTRUEncapsulatorSpi(bcPublicKey,
            resolveSpec(spec, bcPublicKey.getKeyParams()), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCNTRUPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());


        return new NTRUDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, NTRUKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        NTRUParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "NTRU", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(NTRUKeyParameters key) throws InvalidKeyException
    {
        if (ntruParameters != null && ntruParameters != key.getParameters())
        {
            throw new InvalidKeyException("NTRU key mismatch");
        }
    }

    public static class NTRU extends NTRUKEMSpi
    {
        public NTRU()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }
}
