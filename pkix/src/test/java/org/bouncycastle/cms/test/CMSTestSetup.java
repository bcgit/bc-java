package org.bouncycastle.cms.test;

import junit.extensions.TestSetup;
import junit.framework.Test;

import java.security.Security;

class CMSTestSetup extends TestSetup
{
    public CMSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("BCPQC");
        Security.removeProvider("BC");
    }
}
