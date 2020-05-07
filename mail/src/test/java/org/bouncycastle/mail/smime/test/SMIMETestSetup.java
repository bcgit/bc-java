// Copyright (c) 2005 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
package org.bouncycastle.mail.smime.test;

import junit.extensions.TestSetup;
import junit.framework.Test;

import java.security.Security;

class SMIMETestSetup extends TestSetup 
{
    public SMIMETestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security
                .addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("BC");
    }


}
