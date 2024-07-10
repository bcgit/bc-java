package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;

public class SignatureAndHashAlgorithmFactory
{
    public static SignatureAndHashAlgorithm newFromCodePoint(int signatureSchemeCodePoint)
    {
        return new SignatureAndHashAlgorithm((short) (signatureSchemeCodePoint >> 8), (short) (signatureSchemeCodePoint & 0xFF));
    }

    public static int codePointFromSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        int codePoint = (sigAndHashAlgorithm.getHash() << 8) | sigAndHashAlgorithm.getSignature();
        return codePoint;
    }
}
