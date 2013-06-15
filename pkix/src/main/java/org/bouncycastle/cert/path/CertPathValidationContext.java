package org.bouncycastle.cert.path;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Memoable;

public class CertPathValidationContext
    implements Memoable
{
    private Set handledExtensions = new HashSet();

    public void addHandledExtension(ASN1ObjectIdentifier extensionIdentifier)
    {
        this.handledExtensions.add(extensionIdentifier);
    }

    public Memoable copy()
    {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void reset(Memoable other)
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }
}
