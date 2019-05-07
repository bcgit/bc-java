package org.bouncycastle.pqc.crypto.xmss;

/**
 * Interface for XMSS objects that need to be storeable as a byte array.
 *
 * @deprecated use Encodable
 */
public interface XMSSStoreableObjectInterface
{

    /**
     * Create byte representation of object.
     *
     * @return Byte representation of object.
     */
    public byte[] toByteArray();
}
