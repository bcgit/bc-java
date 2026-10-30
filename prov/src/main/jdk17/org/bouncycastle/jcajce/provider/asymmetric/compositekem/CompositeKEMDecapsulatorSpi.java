package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.InvalidKeyException;

import javax.crypto.DecapsulateException;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class CompositeKEMDecapsulatorSpi
    implements KEMSpi.DecapsulatorSpi
{
    private final CompositePrivateKey privateKey;
    private final KTSParameterSpec parameterSpec;
    private final CompositeMLKEMEngine engine;
    private final int encapsulationLength;

    CompositeKEMDecapsulatorSpi(ASN1ObjectIdentifier compositeOID, CompositePrivateKey privateKey, KTSParameterSpec parameterSpec)
        throws InvalidKeyException
    {
        this.privateKey = privateKey;
        this.parameterSpec = parameterSpec;
        this.engine = new CompositeMLKEMEngine(compositeOID);
        try
        {
            this.encapsulationLength = engine.getEncapsulationLength(privateKey);
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException("unable to determine composite ciphertext length: " + e.getMessage(), e);
        }
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException
    {
        algorithm = KemSpiUtil.resolveDecapsulateAlgorithm(encapsulation, from, to, algorithm, engineSecretSize(), engineEncapsulationSize(), parameterSpec);

        byte[] kemSecret;
        try
        {
            kemSecret = engine.decapsulate(privateKey, Arrays.clone(encapsulation));
        }
        catch (Exception e)
        {
            throw new DecapsulateException("composite decapsulation failed: " + e.getMessage(), e);
        }

        return KdfUtil.makeSecretKey(parameterSpec, kemSecret, from, to, algorithm);
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
