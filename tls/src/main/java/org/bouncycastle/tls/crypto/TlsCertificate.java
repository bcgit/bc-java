package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Interface providing the functional representation of a single X.509 certificate.
 */
public interface TlsCertificate
{
    /**
     * @param signatureAlgorithm
     *            {@link SignatureAlgorithm}
     */
    TlsVerifier createVerifier(short signatureAlgorithm) throws IOException;

    /**
     * @return {@link ClientCertificateType}
     */
    short getClientCertificateType() throws IOException;

    byte[] getEncoded() throws IOException;

    byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException;

    BigInteger getSerialNumber();

    /**
     * @param connectionEnd
     *            {@link ConnectionEnd}
     * @param keyExchangeAlgorithm
     *            {@link KeyExchangeAlgorithm}
     */
    // TODO[tls-ops] This is expected to be only transitional and eventually redundant
    TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException;
}
