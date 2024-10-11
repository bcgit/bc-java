package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcCFBSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;

import java.util.Date;

/**
 * Bouncy Castle implementation of {@link OpenPGPV6KeyGenerator}.
 */
public class BcOpenPGPV6KeyGenerator
        extends OpenPGPV6KeyGenerator
{

    /**
     * Create a new key generator for OpenPGP v6 keys.
     */
    public BcOpenPGPV6KeyGenerator()
    {
        this(new Date());
    }

    /**
     * Create a new key generator for OpenPGP v6 keys.
     * The key creation time will be set to {@code creationTime}
     *
     * @param creationTime creation time of the generated OpenPGP key
     */
    public BcOpenPGPV6KeyGenerator(Date creationTime)
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime, true);
    }

    /**
     * Create a new key generator for OpenPGP v6 keys.
     * Signatures on the key will be generated using the specified {@code signatureHashAlgorithm}.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm to be used for signature generation
     */
    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm)
    {
        this(signatureHashAlgorithm, new Date(), true);
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm used for signatures on the key
     * @param creationTime           creation time of the key and signatures
     */
    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
    {
        super(
                new BcPGPKeyPairGeneratorProvider(),
                new BcPGPContentSignerBuilderProvider(signatureHashAlgorithm),
                new BcPGPDigestCalculatorProvider(),
                keyEncryptorFactory(aeadProtection),
                creationTime);
    }

    private static PBESecretKeyEncryptorFactory keyEncryptorFactory(boolean aeadProtection)
    {
        if (aeadProtection)
        {
            return new BcAEADSecretKeyEncryptorFactory();
        }
        else
        {
            return new BcCFBSecretKeyEncryptorFactory();
        }
    }
}
