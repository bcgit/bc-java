package org.bouncycastle.tsp.ers;

import java.util.Date;

import org.bouncycastle.util.Selector;

public class ERSEvidenceRecordSelector
    implements Selector<ERSEvidenceRecord>
{
    private final ERSData data;

    public ERSEvidenceRecordSelector(ERSData data)
    {
        this.data = data;
    }

    public ERSData getData()
    {
        return data;
    }

    public boolean match(ERSEvidenceRecord obj)
    {
        try
        {
            if (obj.isContaining(data, new Date()))
            {
                try
                {
                    obj.validatePresent(data, new Date());

                    return true;
                }
                catch (Exception e)
                {
                    return false;
                }
            }

            return false;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public Object clone()
    {
        return null;
    }
}
