package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
