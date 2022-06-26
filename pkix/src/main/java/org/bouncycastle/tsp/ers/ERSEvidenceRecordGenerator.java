package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;

public class ERSEvidenceRecordGenerator
{
    private final DigestCalculatorProvider digCalcProv;

    public ERSEvidenceRecordGenerator(DigestCalculatorProvider digCalcProv)
    {
        this.digCalcProv = digCalcProv;
    }

    public ERSEvidenceRecord generate(ERSArchiveTimeStamp archiveTimeStamp)
        throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            new EvidenceRecord(null, null, archiveTimeStamp.toASN1Structure()), digCalcProv);
    }

    public List<ERSEvidenceRecord> generate(List<ERSArchiveTimeStamp> archiveTimeStamps)
        throws TSPException, ERSException
    {
        List<ERSEvidenceRecord> list = new ArrayList<ERSEvidenceRecord>(archiveTimeStamps.size());
        for (int i = 0; i != archiveTimeStamps.size(); i++)
        {
            list.add(new ERSEvidenceRecord(
                    new EvidenceRecord(null, null, ((ERSArchiveTimeStamp)archiveTimeStamps.get(i)).toASN1Structure()), digCalcProv));
        }

        return list;
    }
}
