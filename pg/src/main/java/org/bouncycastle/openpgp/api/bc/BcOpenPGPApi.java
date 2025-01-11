package org.bouncycastle.openpgp.api.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;

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
    public OpenPGPV6KeyGenerator generateKey()
            throws PGPException
    {
        return new BcOpenPGPV6KeyGenerator();
    }

    @Override
    public OpenPGPV6KeyGenerator generateKey(Date creationTime)
            throws PGPException
    {
        return new BcOpenPGPV6KeyGenerator(creationTime);
    }

    @Override
    public OpenPGPV6KeyGenerator generateKey(Date creationTime,
                                             boolean aeadProtection)
            throws PGPException
    {
        return new BcOpenPGPV6KeyGenerator(creationTime, aeadProtection);
    }
}
