package org.bouncycastle.gpg.keybox;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class UserID
{
    private final long offsetToUserId;
    private final long lengthOfUserId;
    private final int userIdFlags;
    private final int validity;
    private final int reserved;
    private final byte[] userID;

    private UserID(long offsetToUserId, long lengthOfUserId, int userIdFlags, int validity, int reserved, byte[] userID)
    {
        this.offsetToUserId = offsetToUserId;
        this.lengthOfUserId = lengthOfUserId;
        this.userIdFlags = userIdFlags;
        this.validity = validity;
        this.reserved = reserved;
        this.userID = userID;
    }

    static UserID getInstance(Object src, int base)
        throws IOException
    {
        if (src instanceof UserID)
        {
            return (UserID)src;
        }

        KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(src);

        long offsetToUserId = buffer.u32();
        long lengthOfUserId = buffer.u32();
        int specialUserIdFlags = buffer.u16();


        int validity = buffer.u8();
        int reserved = buffer.u8();

        byte[] userID = buffer.rangeOf(
            (int)(base + offsetToUserId),
            (int)(base + offsetToUserId + lengthOfUserId));


        return new UserID(offsetToUserId, lengthOfUserId, specialUserIdFlags, validity, reserved, userID);

    }


    public long getOffsetToUserId()
    {
        return offsetToUserId;
    }

    public long getLengthOfUserId()
    {
        return lengthOfUserId;
    }

    public long getUserIdFlags()
    {
        return userIdFlags;
    }

    public int getValidity()
    {
        return validity;
    }

    public int getReserved()
    {
        return reserved;
    }

    public byte[] getUserID()
    {
        return Arrays.clone(userID);
    }

    public String getUserIDAsString()
    {
        return Strings.fromUTF8ByteArray(userID);
    }
}
