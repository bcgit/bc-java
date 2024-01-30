package org.bouncycastle.mls.codec;

import java.io.IOException;

public class HPKECiphertext
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] kem_output;
    byte[] ciphertext;

    public byte[] getKemOutput()
    {
        return kem_output;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }

    public HPKECiphertext(byte[] kem_output, byte[] ciphertext)
    {
        this.kem_output = kem_output;
        this.ciphertext = ciphertext;
    }

    @SuppressWarnings("unused")
    HPKECiphertext(MLSInputStream stream)
        throws IOException
    {
        kem_output = stream.readOpaque();
        ciphertext = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(kem_output);
        stream.writeOpaque(ciphertext);
    }
}
