package org.bouncycastle.its.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.operator.ContentSigner;

public interface ITSContentSigner
    extends ContentSigner
{
    ITSCertificate getAssociatedCertificate();

    byte[] getAssociatedCertificateDigest();

    AlgorithmIdentifier getDigestAlgorithm();
}
