package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPApi;

import java.io.IOException;
import java.util.Date;

public abstract class APITest
        extends AbstractPacketTest
{
    @Override
    public void performTest()
            throws Exception
    {
        performTestWith(new BcOpenPGPApi());
        performTestWith(new JcaOpenPGPApi(new BouncyCastleProvider()));
    }

    public Date currentTimeRounded()
    {
        Date now = new Date();
        return new Date((now.getTime() / 1000) * 1000); // rounded to seconds
    }

    protected abstract void performTestWith(OpenPGPApi api)
        throws PGPException, IOException;
}
