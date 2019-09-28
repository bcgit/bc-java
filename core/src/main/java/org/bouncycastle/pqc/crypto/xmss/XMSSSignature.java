package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Signature.
 */
public final class XMSSSignature
    extends XMSSReducedSignature
    implements XMSSStoreableObjectInterface, Encodable
{

    private final int index;
    private final byte[] random;

    private XMSSSignature(Builder builder)
    {
        super(builder);
        index = builder.index;
        int n = getParams().getTreeDigestSize();
        byte[] tmpRandom = builder.random;
        if (tmpRandom != null)
        {
            if (tmpRandom.length != n)
            {
                throw new IllegalArgumentException("size of random needs to be equal to size of digest");
            }
            random = tmpRandom;
        }
        else
        {
            random = new byte[n];
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
        extends XMSSReducedSignature.Builder
    {

        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private byte[] random = null;

        public Builder(XMSSParameters params)
        {
            super(params);
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withRandom(byte[] val)
        {
            random = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSignature(byte[] val)
        {
            if (val == null)
            {
                throw new NullPointerException("signature == null");
            }
            int n = params.getTreeDigestSize();
            int len = params.getWOTSPlus().getParams().getLen();
            int height = params.getHeight();
            int indexSize = 4;
            int randomSize = n;
            int signatureSize = len * n;
            int authPathSize = height * n;
            int position = 0;
            /* extract index */
            index = Pack.bigEndianToInt(val, position);
            position += indexSize;
			/* extract random */
            random = XMSSUtil.extractBytesAtOffset(val, position, randomSize);
            position += randomSize;
            withReducedSignature(XMSSUtil.extractBytesAtOffset(val, position, signatureSize + authPathSize));
            return this;
        }

        public XMSSSignature build()
        {
            return new XMSSSignature(this);
        }
    }

    /**
     * @deprecated use getEncoded() this method will become private.
     * @return
     */
    public byte[] toByteArray()
    {
		/* index || random || signature || authentication path */
        int n = getParams().getTreeDigestSize();
        int indexSize = 4;
        int randomSize = n;
        int signatureSize = getParams().getWOTSPlus().getParams().getLen() * n;
        int authPathSize = getParams().getHeight() * n;
        int totalSize = indexSize + randomSize + signatureSize + authPathSize;
        byte[] out = new byte[totalSize];
        int position = 0;
		/* copy index */
        Pack.intToBigEndian(index, out, position);
        position += indexSize;
		/* copy random */
        XMSSUtil.copyBytesAtOffset(out, random, position);
        position += randomSize;
		/* copy signature */
        byte[][] signature = getWOTSPlusSignature().toByteArray();
        for (int i = 0; i < signature.length; i++)
        {
            XMSSUtil.copyBytesAtOffset(out, signature[i], position);
            position += n;
        }
		/* copy authentication path */
        for (int i = 0; i < getAuthPath().size(); i++)
        {
            byte[] value = getAuthPath().get(i).getValue();
            XMSSUtil.copyBytesAtOffset(out, value, position);
            position += n;
        }
        return out;
    }

    public int getIndex()
    {
        return index;
    }

    public byte[] getRandom()
    {
        return XMSSUtil.cloneArray(random);
    }
}
