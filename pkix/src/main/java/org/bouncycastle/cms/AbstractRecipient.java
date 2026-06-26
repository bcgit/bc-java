package org.bouncycastle.cms;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Base class for the CMS recipient implementations, carrying the optional restrictions on which
 * content-encryption algorithms a recipient is willing to recover content for, and on the minimum
 * AEAD authentication tag size it will accept.
 */
public abstract class AbstractRecipient
{
    private Set<ASN1ObjectIdentifier> allowedContentAlgorithms;
    private int minimumTagSizeInBits = 0;

    protected final void setAllowedContentAlgorithmSet(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
    {
        this.allowedContentAlgorithms = new HashSet<ASN1ObjectIdentifier>(allowedContentAlgorithms);
    }

    protected final boolean isContentAlgorithmAllowed(ASN1ObjectIdentifier contentAlgorithm)
    {
        return (allowedContentAlgorithms == null) || allowedContentAlgorithms.contains(contentAlgorithm);
    }

    protected final void setMinimumTagSizeInBits(int tagSizeInBits)
    {
        this.minimumTagSizeInBits = tagSizeInBits;
    }

    /**
     * Refuse an AEAD content algorithm whose authentication tag is shorter than the configured
     * minimum. A no-op when no minimum is set or when the content algorithm is not AEAD.
     *
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier (carries the AEAD ICV length).
     * @throws CMSTagLengthException if the tag size is below the configured minimum.
     */
    protected final void checkTagSize(AlgorithmIdentifier contentAlgorithm)
        throws CMSTagLengthException
    {
        if (minimumTagSizeInBits > 0)
        {
            int macLenOctets = CMSUtils.getAEADMacLength(contentAlgorithm);

            if (macLenOctets >= 0 && macLenOctets * 8 < minimumTagSizeInBits)
            {
                throw new CMSTagLengthException("AEAD tag size " + (macLenOctets * 8)
                    + " bits below required minimum " + minimumTagSizeInBits + " bits");
            }
        }
    }
}
