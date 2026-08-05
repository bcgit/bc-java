package org.bouncycastle.gpg.keybox;

import java.io.IOException;

/**
 * A PGP blob holds key material.
 */
public class CertificateBlob
    extends KeyBlob
{
    private CertificateBlob(int base, long length,
                            BlobType type,
                            int version,
                            KeyBlobContent content)
    {
        super(base, length, type, version, content);
    }


    static Blob parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer, BlobVerifier blobVerifier)
        throws IOException
    {

        KeyBlobContent content = KeyBlobContent.parse(base, length, buffer, blobVerifier);

        return new CertificateBlob(base, length, type, version, content);
    }

    /**
     * Return the encoded certificate.
     * <p>
     * This is the raw certificate data, if you are using the JCA then you can
     * convert it back to an X509 Certificate using.
     * <p>
     * Example:
     * byte[] certData = keyBlob.getEncodedCertificate();
     * CertificateFactory factory = CertificateFactory.getInstance("X509");
     * certificate = factory.generateCertificate(new ByteArrayInputStream(certData));
     *
     * @return
     */
    public byte[] getEncodedCertificate()
    {
        return getKeyBytes();
    }
}
