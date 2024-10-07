package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.HashAlgorithmTags;
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

    public static final int DEFAULT_SIGNATURE_HASH_ALGORITHM = HashAlgorithmTags.SHA3_512;

    public BcOpenPGPV6KeyGenerator()
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM);
    }

    public BcOpenPGPV6KeyGenerator(Date creationTime)
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime);
    }

    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm)
    {
        this(signatureHashAlgorithm, new Date());
    }

    /**
     * Generate a new OpenPGP key generator for v6 keys.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm used for signatures on the key
     * @param creationTime           creation time of the key and signatures
     */
    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm, Date creationTime)
    {
        super(
                new BcPGPKeyPairGeneratorProvider(),
                new BcPGPContentSignerBuilderProvider(signatureHashAlgorithm),
                new BcPGPDigestCalculatorProvider(),
                creationTime);
    }
}
