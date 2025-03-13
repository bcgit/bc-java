package org.bouncycastle.pqc.crypto.xmss;

/**
 * Interface for XMSS objects that need to be storeable as a byte array.
 *
 * @deprecated use Encodable
 */
@Deprecated
public interface XMSSStoreableObjectInterface
{

    /**
     * Create byte representation of object.
     *
     * @return Byte representation of object.
     */
    byte[] toByteArray();
}
