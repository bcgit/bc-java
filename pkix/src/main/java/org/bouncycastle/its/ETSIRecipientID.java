package org.bouncycastle.its;

import org.bouncycastle.oer.its.ieee1609dot2.PKRecipientInfo;
import org.bouncycastle.oer.its.ieee1609dot2.RecipientInfo;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

public class ETSIRecipientID
    implements Selector<ETSIRecipientInfo>
{
    private final HashedId8 id;

    public ETSIRecipientID(byte[] id)
    {
        this(new HashedId8(id));
    }

    public ETSIRecipientID(HashedId8 id)
    {
        this.id = id;
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

        ETSIRecipientID that = (ETSIRecipientID)o;

        return id != null ? id.equals(that.id) : that.id == null;
    }

    @Override
    public int hashCode()
    {
        return id != null ? id.hashCode() : 0;
    }

    public boolean match(ETSIRecipientInfo obj)
    {
        if (obj.getRecipientInfo().getChoice() == RecipientInfo.certRecipInfo)
        {
            PKRecipientInfo objPkInfo = PKRecipientInfo.getInstance(obj.getRecipientInfo().getRecipientInfo());
            return Arrays.areEqual(objPkInfo.getRecipientId().getHashBytes(), this.id.getHashBytes());
        }
        return false;
    }

    public Object clone()
    {
        return this;
    }
}
