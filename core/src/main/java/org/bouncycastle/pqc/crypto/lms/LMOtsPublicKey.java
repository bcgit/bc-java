package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

import static org.bouncycastle.pqc.crypto.lms.LM_OTS.D_MESG;

class LMOtsPublicKey
    implements Encodable
{
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] K;


    public LMOtsPublicKey(LMOtsParameters parameter, byte[] i, int q, byte[] k)
    {
        this.parameter = parameter;
        this.I = i;
        this.q = q;
        this.K = k;
    }

    public static LMOtsPublicKey getInstance(Object src)
        throws Exception
    {
        if (src instanceof LMOtsPublicKey)
        {
            return (LMOtsPublicKey)src;
        }
        else if (src instanceof DataInputStream)
        {
            LMOtsParameters parameter = LMOtsParameters.getParametersForType(((DataInputStream)src).readInt());
            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);
            int q = ((DataInputStream)src).readInt();

            byte[] K = new byte[parameter.getN()];
            ((DataInputStream)src).readFully(K);

            return new LMOtsPublicKey(parameter, I, q, K);

        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                return getInstance(in);
            }
            finally
            {
                if (in != null) in.close();
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public LMOtsParameters getParameter()
    {
        return parameter;
    }

    public byte[] getI()
    {
        return I;
    }

    public int getQ()
    {
        return q;
    }

    public byte[] getK()
    {
        return K;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        LMOtsPublicKey that = (LMOtsPublicKey)o;

        if (q != that.q)
        {
            return false;
        }
        if (parameter != null ? !parameter.equals(that.parameter) : that.parameter != null)
        {
            return false;
        }
        if (!Arrays.equals(I, that.I))
        {
            return false;
        }
        return Arrays.equals(K, that.K);
    }

    @Override
    public int hashCode()
    {
        int result = parameter != null ? parameter.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(I);
        result = 31 * result + q;
        result = 31 * result + Arrays.hashCode(K);
        return result;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose()
            .u32str(parameter.getType())
            .bytes(I)
            .u32str(q)
            .bytes(K).build();
    }

    LMSContext createOtsContext(LMOtsSignature signature)
    {
        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());

        LmsUtils.byteArray(I, ctx);
        LmsUtils.u32str(q, ctx);
        LmsUtils.u16str(D_MESG, ctx);
        LmsUtils.byteArray(signature.getC(), ctx);

        return new LMSContext(this, signature, ctx);
    }

    LMSContext createOtsContext(LMSSignature signature)
    {
        Digest ctx = DigestUtil.getDigest(parameter.getDigestOID());

        LmsUtils.byteArray(I, ctx);
        LmsUtils.u32str(q, ctx);
        LmsUtils.u16str(D_MESG, ctx);
        LmsUtils.byteArray(signature.getOtsSignature().getC(), ctx);

        return new LMSContext(this, signature, ctx);
    }
}
