package org.bouncycastle.cert.test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.operator.DigestCalculator;


class SHA256DigestCalculator
    implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    }

    public OutputStream getOutputStream()
    {
        return bOut;
    }

    public byte[] getDigest()
    {
        byte[] bytes = bOut.toByteArray();

        bOut.reset();

        Digest sha256 = new SHA256Digest();

        sha256.update(bytes, 0, bytes.length);

        byte[] digest = new byte[sha256.getDigestSize()];

        sha256.doFinal(digest, 0);

        return digest;
    }
}
