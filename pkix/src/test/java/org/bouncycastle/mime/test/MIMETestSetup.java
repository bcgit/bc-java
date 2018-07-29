
package org.bouncycastle.mime.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class MIMETestSetup
    extends TestSetup
{
    public MIMETestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
