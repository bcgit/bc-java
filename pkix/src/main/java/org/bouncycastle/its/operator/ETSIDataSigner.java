package org.bouncycastle.its.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;

public interface ETSIDataSigner
{
    Signature getSignature();
    AlgorithmIdentifier getDigestAlgorithm();
    OutputStream getOutputStream();
}
