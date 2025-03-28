package org.bouncycastle.openpgp.api.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Date;

/**
 * JCA/JCE implementation of the {@link OpenPGPKeyGenerator}.
 */
public class JcaOpenPGPKeyGenerator
    extends OpenPGPKeyGenerator
{

    public JcaOpenPGPKeyGenerator(int version, Provider provider)
        throws PGPException
    {
        this(version, new Date(), provider);
    }

    public JcaOpenPGPKeyGenerator(int version, Date creationTime, Provider provider)
        throws PGPException
    {
        this(version, creationTime, true, provider);
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param creationTime           creation time of the key and signatures
     */
    public JcaOpenPGPKeyGenerator(int version, Date creationTime, boolean aeadProtection, Provider provider)
        throws PGPException
    {
        super(
                new JcaOpenPGPImplementation(provider, new SecureRandom()),
                version,
                aeadProtection,
                creationTime);
    }
}
