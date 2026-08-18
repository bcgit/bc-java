package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.kems.CMCEKEMExtractor;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class CMCEDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final CMCEPrivateKeyParameters privateKeyParams;
    private final KTSParameterSpec parameterSpec;
    private final int encapsulationLength;

    CMCEDecapsulatorSpi(BCCMCEPrivateKey privateKey, KTSParameterSpec parameterSpec)
    {
        this.privateKeyParams = privateKey.getKeyParams();
        this.parameterSpec = parameterSpec;
        this.encapsulationLength = privateKeyParams.getParameters().getEncapsulationLength();
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");
        Objects.requireNonNull(encapsulation, "null encapsulation");

        if (encapsulation.length != engineEncapsulationSize())
        {
            throw new DecapsulateException("incorrect encapsulation size");
        }

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        // CMCEEngine allocates its digest per call, so a shared extractor would be safe here and
        // the families whose engines are also safe - NTRU LPRime, SMAUG-T and the four older ones -
        // do share one. This builds per call only to stay symmetric with the FrodoKEM sibling added
        // beside it, whose engine keeps a mutable digest; there is no correctness need for it.
        byte[] kemSecret = new CMCEKEMExtractor(privateKeyParams).extractSecret(encapsulation);
        byte[] kdfSecret = KdfUtil.makeKeyBytes(parameterSpec, kemSecret);

        try
        {
            return new SecretKeySpec(kdfSecret, from, to - from, algorithm);
        }
        finally
        {
            Arrays.clear(kdfSecret);
        }
    }

    @Override
    public int engineSecretSize()
    {
        return parameterSpec.getKeySize() / 8;
    }

    @Override
    public int engineEncapsulationSize()
    {
        return encapsulationLength;
    }
}
