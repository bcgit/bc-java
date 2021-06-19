package org.bouncycastle.its;

import org.bouncycastle.operator.ContentSigner;

public interface ITSContentSigner
    extends ContentSigner
{
    ITSCertificate getAssociatedCertificate();
}
