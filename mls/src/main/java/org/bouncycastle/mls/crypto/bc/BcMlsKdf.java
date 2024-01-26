package org.bouncycastle.mls.crypto.bc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.MlsKdf;

public class BcMlsKdf
    implements MlsKdf
{
    private final HKDFBytesGenerator kdf;

    public BcMlsKdf(Digest digest)
    {
        kdf = new HKDFBytesGenerator(digest);
    }

    @Override
    public Digest getDigest()
    {
        return kdf.getDigest();
    }

    @Override
    public int getHashLength()
    {
        return kdf.getDigest().getDigestSize();
    }

    @Override
    public byte[] extract(byte[] salt, byte[] ikm)
    {
        byte[] out = kdf.extractPRK(salt, ikm);
        kdf.getDigest().reset();
        return out;
    }

    @Override
    public byte[] expand(byte[] prk, byte[] info, int length)
    {
        byte[] okm = new byte[length];
        kdf.init(HKDFParameters.skipExtractParameters(prk, info));
        kdf.generateBytes(okm, 0, okm.length);
        kdf.getDigest().reset();
        return okm;
    }

    @Override
    public byte[] expandWithLabel(byte[] secret, String label, byte[] context, int length)
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write((short)length);
        stream.writeOpaque(("MLS 1.0 " + label).getBytes(StandardCharsets.UTF_8));
        stream.writeOpaque(context);
        byte[] kdfLabel = stream.toByteArray();
        return expand(secret, kdfLabel, length);
    }

}
