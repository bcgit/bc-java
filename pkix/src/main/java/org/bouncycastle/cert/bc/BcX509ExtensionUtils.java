package org.bouncycastle.cert.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.DigestCalculator;

public class BcX509ExtensionUtils
    extends X509ExtensionUtils
{
    /**
     * Create a utility class pre-configured with a SHA-1 digest calculator based on the
     * BC implementation.
     */
    public BcX509ExtensionUtils()
    {
        super(new SHA1DigestCalculator());
    }

    public BcX509ExtensionUtils(DigestCalculator calculator)
    {
        super(calculator);
    }

    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(
        AsymmetricKeyParameter publicKey)
        throws IOException
    {
        return super.createAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }

    /**
     * Return a RFC 3280 type 1 key identifier. As in:
     * <pre>
     * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
     * value of the BIT STRING subjectPublicKey (excluding the tag,
     * length, and number of unused bits).
     * </pre>
     * @param publicKey the key object containing the key identifier is to be based on.
     * @return the key identifier.
     */
    public SubjectKeyIdentifier createSubjectKeyIdentifier(
        AsymmetricKeyParameter publicKey)
        throws IOException
    {
        return super.createSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }

    private static class SHA1DigestCalculator
        implements DigestCalculator
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        }

        public OutputStream getOutputStream()
        {
            return bOut;
        }

        public byte[] getDigest()
        {
            byte[] bytes = bOut.toByteArray();

            bOut.reset();

            Digest sha1 = new SHA1Digest();

            sha1.update(bytes, 0, bytes.length);

            byte[] digest = new byte[sha1.getDigestSize()];

            sha1.doFinal(digest, 0);

            return digest;
        }
    }
}
