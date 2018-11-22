package org.bouncycastle.pkix.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;

import org.bouncycastle.jcajce.util.JcaJceHelper;

interface PKIXJcaJceHelper
    extends JcaJceHelper
{
    CertPathBuilder createCertPathBuilder(String type)
        throws NoSuchAlgorithmException, NoSuchProviderException;
}
