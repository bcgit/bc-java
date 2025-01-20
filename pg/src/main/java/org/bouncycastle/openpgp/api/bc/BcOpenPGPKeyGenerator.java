package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;

import java.util.Date;

/**
 * Bouncy Castle implementation of {@link OpenPGPKeyGenerator}.
 */
public class BcOpenPGPKeyGenerator
    extends OpenPGPKeyGenerator
{

    /**
     * Create a new key generator for OpenPGP v6 keys.
     *
     * @param version key version
     */
    public BcOpenPGPKeyGenerator(int version)
            throws PGPException
    {
        this(version, new Date());
    }

    /**
     * Create a new key generator for OpenPGP v6 keys.
     * The key creation time will be set to {@code creationTime}
     *
     * @param version key version
     * @param creationTime creation time of the generated OpenPGP key
     */
    public BcOpenPGPKeyGenerator(int version, Date creationTime)
            throws PGPException
    {
        this(version, creationTime, true);
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param version key version
     * @param creationTime           creation time of the key and signatures
     * @param aeadProtection whether the key shall be protected using AEAD. If false, the key is protected using CFB.
     */
    public BcOpenPGPKeyGenerator(int version, Date creationTime, boolean aeadProtection)
        throws PGPException
    {
        super(new BcOpenPGPImplementation(), version, aeadProtection, creationTime);
    }
}
