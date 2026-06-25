package org.bouncycastle.cms;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Base class for the CMS recipient implementations, carrying the optional restriction on which
 * content-encryption algorithms a recipient is willing to recover content for.
 */
public abstract class AbstractRecipient
{
    private Set<ASN1ObjectIdentifier> allowedContentAlgorithms;

    protected final void setAllowedContentAlgorithmSet(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
    {
        this.allowedContentAlgorithms = new HashSet<ASN1ObjectIdentifier>(allowedContentAlgorithms);
    }

    protected final boolean isContentAlgorithmAllowed(ASN1ObjectIdentifier contentAlgorithm)
    {
        return (allowedContentAlgorithms == null) || allowedContentAlgorithms.contains(contentAlgorithm);
    }
}
