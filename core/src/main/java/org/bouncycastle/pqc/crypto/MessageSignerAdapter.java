package org.bouncycastle.pqc.crypto;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.util.Arrays;

public final class MessageSignerAdapter
    implements Signer
{
    private final Buffer buffer = new Buffer();

    private final MessageSigner messageSigner;

    public MessageSignerAdapter(MessageSigner messageSigner)
    {
        if (messageSigner == null)
        {
            throw new NullPointerException("'messageSigner' cannot be null");
        }

        this.messageSigner = messageSigner;
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        messageSigner.init(forSigning, param);
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
    {
        return messageSigner.generateSignature(getMessage());
    }

    public boolean verifySignature(byte[] signature)
    {
        return messageSigner.verifySignature(getMessage(), signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    private byte[] getMessage()
    {
        try
        {
            return buffer.toByteArray();
        }
        finally
        {
            reset();
        }
    }

    private static final class Buffer extends ByteArrayOutputStream
    {
        public synchronized void reset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
