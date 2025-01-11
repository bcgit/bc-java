package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;

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
            throws PGPException
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
            throws PGPException
    {
        this(creationTime, true);
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param creationTime           creation time of the key and signatures
     * @param aeadProtection whether the key shall be protected using AEAD. If false, the key is protected using CFB.
     */
    public BcOpenPGPV6KeyGenerator(Date creationTime, boolean aeadProtection)
        throws PGPException
    {
        super(new BcOpenPGPImplementation(), aeadProtection, creationTime);
    }
}
