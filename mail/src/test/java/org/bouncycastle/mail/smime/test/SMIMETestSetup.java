// Copyright (c) 2005 The Legion Of The Bouncy Castle (https://www.bouncycastle.org)
package org.bouncycastle.mail.smime.test;

import java.security.Security;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;

import junit.extensions.TestSetup;
import junit.framework.Test;

class SMIMETestSetup extends TestSetup 
{
    private CommandMap originalMap = null;

    public SMIMETestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security
                .addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        MailcapCommandMap _mailcap = (MailcapCommandMap)CommandMap
                .getDefaultCommandMap();

        _mailcap
                .addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        _mailcap
                .addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        _mailcap
                .addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        _mailcap
                .addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        _mailcap
                .addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        originalMap = CommandMap.getDefaultCommandMap();
        CommandMap.setDefaultCommandMap(_mailcap);
    }

    protected void tearDown()
    {
        CommandMap.setDefaultCommandMap(originalMap);
        originalMap = null;
        Security.removeProvider("BC");
    }


}
