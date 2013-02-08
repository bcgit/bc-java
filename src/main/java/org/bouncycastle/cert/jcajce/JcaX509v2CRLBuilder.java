package org.bouncycastle.cert.jcajce;

import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;

public class JcaX509v2CRLBuilder
    extends X509v2CRLBuilder
{
    public JcaX509v2CRLBuilder(X500Principal issuer, Date now)
    {
        super(X500Name.getInstance(issuer.getEncoded()), now);
    }

    public JcaX509v2CRLBuilder(X509Certificate issuerCert, Date now)
    {
        this(issuerCert.getSubjectX500Principal(), now);
    }
}
