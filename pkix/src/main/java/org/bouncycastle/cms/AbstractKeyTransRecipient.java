package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public abstract class AbstractKeyTransRecipient
    extends AbstractRecipient
    implements KeyTransRecipient
{
    protected boolean isGOST(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isGOST(algorithmOID);
    }
}
