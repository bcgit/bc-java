package org.bouncycastle.cert.path;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Memoable;

public class CertPathValidationContext
    implements Memoable
{
    private Set criticalExtensions;

    private Set handledExtensions = new HashSet();
    private boolean endEntity;
    private int index;

    public CertPathValidationContext(Set criticalExtensionsOIDs)
    {
        this.criticalExtensions = criticalExtensionsOIDs;
    }

    public void addHandledExtension(ASN1ObjectIdentifier extensionIdentifier)
    {
        this.handledExtensions.add(extensionIdentifier);
    }

    public void setIsEndEntity(boolean isEndEntity)
    {
        this.endEntity = isEndEntity;
    }

    public Set getUnhandledCriticalExtensionOIDs()
    {
        Set rv = new HashSet(criticalExtensions);

        rv.removeAll(handledExtensions);

        return rv;
    }

    /**
     * Returns true if the current certificate is the end-entity certificate.
     *
     * @return if current cert end-entity, false otherwise.
     */
    public boolean isEndEntity()
    {
        return endEntity;
    }

    public Memoable copy()
    {
        CertPathValidationContext c = new CertPathValidationContext(new HashSet(this.criticalExtensions));

        c.handledExtensions = new HashSet(this.handledExtensions);
        c.endEntity = this.endEntity;
        c.index = this.index;

        return c;
    }

    public void reset(Memoable other)
    {
        CertPathValidationContext c = (CertPathValidationContext) other;

        this.criticalExtensions = new HashSet(c.criticalExtensions);
        this.handledExtensions = new HashSet(c.handledExtensions);
        this.endEntity = c.endEntity;
        this.index = c.index;
    }
}
