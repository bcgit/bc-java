package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;

import java.util.Date;

public class BcOpenPGPApi
        extends OpenPGPApi
{
    public BcOpenPGPApi()
    {
        super(new BcOpenPGPImplementation());
    }

    public BcOpenPGPApi(OpenPGPPolicy policy)
    {
        super(new BcOpenPGPImplementation(), policy);
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
