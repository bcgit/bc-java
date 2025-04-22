package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;

import java.util.Date;

/**
 * Implementation of {@link OpenPGPApi} using Bouncy Castles implementation of OpenPGP classes.
 */
public class BcOpenPGPApi
        extends OpenPGPApi
{
    public BcOpenPGPApi()
    {
        this(new BcOpenPGPImplementation());
    }

    public BcOpenPGPApi(OpenPGPImplementation implementation)
    {
        super(implementation);
    }

    public BcOpenPGPApi(OpenPGPPolicy policy)
    {
        this(new BcOpenPGPImplementation(), policy);
    }

    public BcOpenPGPApi(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        super(implementation, policy);
    }

    @Override
    public OpenPGPKeyGenerator generateKey(int version)
            throws PGPException
    {
        return new BcOpenPGPKeyGenerator(version);
    }

    @Override
    public OpenPGPKeyGenerator generateKey(int version,
                                           Date creationTime)
            throws PGPException
    {
        return new BcOpenPGPKeyGenerator(version, creationTime);
    }

    @Override
    public OpenPGPKeyGenerator generateKey(int version,
                                           Date creationTime,
                                           boolean aeadProtection)
            throws PGPException
    {
        return new BcOpenPGPKeyGenerator(version, creationTime, aeadProtection);
    }
}
