package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.params.CMCEKeyParameters;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * {@link javax.crypto.KEM} support for the Classic McEliece KEM as standardised in
 * ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13, registered as {@code KEM.CMCE} plus one
 * parameter-set locked service per {@link CMCEParameters} set.
 * <p>
 * With a null spec the shared secret is the mechanism's own 256-bit session key - the
 * interoperable form. A {@link KTSParameterSpec} KDF may optionally be layered on top for
 * generic use.
 */
public abstract class CMCEKEMSpi
    implements KEMSpi
{
    private final CMCEParameters cmceParameters;

    CMCEKEMSpi(CMCEParameters cmceParameters)
    {
        this.cmceParameters = cmceParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCCMCEPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());

        return new CMCEEncapsulatorSpi(bcPublicKey, resolveSpec(spec, bcPublicKey.getKeyParams()), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCCMCEPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());

        return new CMCEDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, CMCEKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        CMCEParameters keyParameters = key.getParameters();
        int sessionKeySize = keyParameters.getSessionKeySize();

        if (spec == null)
        {
            // Do not wrap key, no KDF
            return new KTSParameterSpec.Builder("Generic", sessionKeySize).withNoKdf().build();
        }

        if (!(spec instanceof KTSParameterSpec ktsSpec))
        {
            throw new InvalidAlgorithmParameterException("CMCE can only accept KTSParameterSpec");
        }

        // KTSParameterSpec does not check its own key size, and a non-positive one otherwise fails
        // as an undeclared unchecked exception out of encapsulate()/decapsulate() rather than here.
        if (ktsSpec.getKeySize() <= 0)
        {
            throw new InvalidAlgorithmParameterException("KTSParameterSpec key size must be positive: "
                + ktsSpec.getKeySize());
        }

        // Without a KDF the secret is the session key itself, so a longer one cannot be produced.
        // javax.crypto.KEM requires secretSize() to be honest - and validates encapsulate()'s range
        // against it - so refuse the spec here rather than silently shortening the key the way the
        // KTS wrapping path does (WrapUtil clamps the KEK to the secret it has).
        if (ktsSpec.getKdfAlgorithm() == null && ktsSpec.getKeySize() > sessionKeySize)
        {
            throw new InvalidAlgorithmParameterException("no KDF specified and " + keyParameters.getName()
                + " produces a " + sessionKeySize + " bit secret, " + ktsSpec.getKeySize() + " requested");
        }

        return ktsSpec;
    }

    private void checkKeyParameters(CMCEKeyParameters key) throws InvalidKeyException
    {
        if (cmceParameters != null && cmceParameters != key.getParameters())
        {
            throw new InvalidKeyException("CMCE key mismatch");
        }
    }

    public static class Base extends CMCEKEMSpi
    {
        public Base()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class Mceliece460896 extends CMCEKEMSpi
    {
        public Mceliece460896()
        {
            super(CMCEParameters.mceliece460896);
        }
    }

    public static class Mceliece460896F extends CMCEKEMSpi
    {
        public Mceliece460896F()
        {
            super(CMCEParameters.mceliece460896f);
        }
    }

    public static class Mceliece460896Pc extends CMCEKEMSpi
    {
        public Mceliece460896Pc()
        {
            super(CMCEParameters.mceliece460896pc);
        }
    }

    public static class Mceliece460896Pcf extends CMCEKEMSpi
    {
        public Mceliece460896Pcf()
        {
            super(CMCEParameters.mceliece460896pcf);
        }
    }

    public static class Mceliece6688128 extends CMCEKEMSpi
    {
        public Mceliece6688128()
        {
            super(CMCEParameters.mceliece6688128);
        }
    }

    public static class Mceliece6688128F extends CMCEKEMSpi
    {
        public Mceliece6688128F()
        {
            super(CMCEParameters.mceliece6688128f);
        }
    }

    public static class Mceliece6688128Pc extends CMCEKEMSpi
    {
        public Mceliece6688128Pc()
        {
            super(CMCEParameters.mceliece6688128pc);
        }
    }

    public static class Mceliece6688128Pcf extends CMCEKEMSpi
    {
        public Mceliece6688128Pcf()
        {
            super(CMCEParameters.mceliece6688128pcf);
        }
    }

    public static class Mceliece6960119 extends CMCEKEMSpi
    {
        public Mceliece6960119()
        {
            super(CMCEParameters.mceliece6960119);
        }
    }

    public static class Mceliece6960119F extends CMCEKEMSpi
    {
        public Mceliece6960119F()
        {
            super(CMCEParameters.mceliece6960119f);
        }
    }

    public static class Mceliece6960119Pc extends CMCEKEMSpi
    {
        public Mceliece6960119Pc()
        {
            super(CMCEParameters.mceliece6960119pc);
        }
    }

    public static class Mceliece6960119Pcf extends CMCEKEMSpi
    {
        public Mceliece6960119Pcf()
        {
            super(CMCEParameters.mceliece6960119pcf);
        }
    }

    public static class Mceliece8192128 extends CMCEKEMSpi
    {
        public Mceliece8192128()
        {
            super(CMCEParameters.mceliece8192128);
        }
    }

    public static class Mceliece8192128F extends CMCEKEMSpi
    {
        public Mceliece8192128F()
        {
            super(CMCEParameters.mceliece8192128f);
        }
    }

    public static class Mceliece8192128Pc extends CMCEKEMSpi
    {
        public Mceliece8192128Pc()
        {
            super(CMCEParameters.mceliece8192128pc);
        }
    }

    public static class Mceliece8192128Pcf extends CMCEKEMSpi
    {
        public Mceliece8192128Pcf()
        {
            super(CMCEParameters.mceliece8192128pcf);
        }
    }
}
