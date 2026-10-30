package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/*
 *  NOTE: Per javadoc for javax.crypto.KEM, "Encapsulator and Decapsulator objects are also immutable. It is safe to
 *  invoke multiple encapsulate and decapsulate methods on the same Encapsulator or Decapsulator object at the same
 *  time. Each invocation of encapsulate will generate a new shared secret and key encapsulation message."
 */
class CompositeKEMEncapsulatorSpi
    implements KEMSpi.EncapsulatorSpi
{
    private final CompositePublicKey publicKey;
    private final KTSParameterSpec parameterSpec;
    private final CompositeMLKEMEngine engine;
    private final int encapsulationLength;

    CompositeKEMEncapsulatorSpi(ASN1ObjectIdentifier compositeOID, CompositePublicKey publicKey, KTSParameterSpec parameterSpec,
        SecureRandom random)
        throws InvalidKeyException
    {
        this.publicKey = publicKey;
        this.parameterSpec = parameterSpec;
        // a null random is the API's request for the provider default, which the engine resolves on first use
        this.engine = new CompositeMLKEMEngine(compositeOID, random);
        try
        {
            this.encapsulationLength = engine.getEncapsulationLength(publicKey);
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException("unable to determine composite ciphertext length: " + e.getMessage(), e);
        }
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize());
        Objects.requireNonNull(algorithm, "null algorithm");

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        SecretWithEncapsulation secEnc;
        try
        {
            // the engine keeps only the OID and its random, so one is safe to share across the
            // concurrent encapsulate calls javax.crypto.KEM requires
            secEnc = engine.encapsulate(publicKey);
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException("composite encapsulation failed: " + e.getMessage(), e);
        }

        try
        {
            byte[] encapsulation = secEnc.getEncapsulation();

            SecretKey secretKey = KdfUtil.makeSecretKey(parameterSpec, secEnc.getSecret(), from, to, algorithm);

            return new KEM.Encapsulated(secretKey, encapsulation, null);
        }
        finally
        {
            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                // ignore
            }
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
