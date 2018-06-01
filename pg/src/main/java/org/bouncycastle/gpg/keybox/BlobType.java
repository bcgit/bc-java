package org.bouncycastle.gpg.keybox;

public enum BlobType
{
    EMPTY_BLOB(0),
    FIRST_BLOB(1),
    OPEN_PGP_BLOB(2),
    X509_BLOB(3);

    private final int byteValue;

    BlobType(int byteValue)
    {
        this.byteValue = byteValue;
    }

    public static BlobType fromByte(int byteVal)
    {
        for (BlobType blobType : BlobType.values())
        {
            if (blobType.byteValue == byteVal)
            {
                return blobType;
            }
        }
        throw new IllegalArgumentException("Unknown blob type " + Integer.toHexString(byteVal));
    }

    public int getByteValue()
    {
        return byteValue;
    }

}
