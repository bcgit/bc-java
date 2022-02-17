package org.bouncycastle.its.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.its.ITSCertificate;

public interface ITSContentSigner
{
    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    /**
     * Returns a signature based on the current data written to the stream, since the
     * start or the last call to getSignature().
     *
     * @return bytes representing the signature.
     */
    byte[] getSignature();

    ITSCertificate getAssociatedCertificate();

    byte[] getAssociatedCertificateDigest();

    AlgorithmIdentifier getDigestAlgorithm();

    ASN1ObjectIdentifier getCurveID();

    /**
     * Return true if this ContentSigner is for self signing. False otherwise.
     *
     * @return true if for self-signing.
     */
    boolean isForSelfSigning();
}
