package org.bouncycastle.tsp.ers;

import java.util.Date;

import org.bouncycastle.util.Selector;

/**
 * Selector matching the {@link ERSEvidenceRecord}s that contain, and validate the
 * presence of, a given data object/group at a particular date. Used to query an
 * {@link ERSEvidenceRecordStore}.
 */
public class ERSEvidenceRecordSelector
    implements Selector<ERSEvidenceRecord>
{
    private final ERSData data;
    private final Date date;

    public ERSEvidenceRecordSelector(ERSData data)
    {
        this(data, new Date());
    }

    public ERSEvidenceRecordSelector(ERSData data, Date atDate)
    {
        this.data = data;
        this.date = new Date(atDate.getTime());
    }

    public ERSData getData()
    {
        return data;
    }

    public boolean match(ERSEvidenceRecord obj)
    {
        try
        {
            if (obj.isContaining(data, date))
            {
                try
                {
                    obj.validatePresent(data, date);

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
        return this;
    }
}
