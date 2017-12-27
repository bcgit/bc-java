package org.bouncycastle.cert.path;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Integers;

class CertPathValidationResultBuilder
{
    private final CertPathValidationContext context;
    private final List<Integer> certIndexes = new ArrayList<Integer>();
    private final List<Integer> ruleIndexes = new ArrayList<Integer>();
    private final List<CertPathValidationException> exceptions = new ArrayList<CertPathValidationException>();

    CertPathValidationResultBuilder(CertPathValidationContext context)
    {
        this.context = context;
    }

    public CertPathValidationResult build()
    {
        if (exceptions.isEmpty())
        {
            return new CertPathValidationResult(context);
        }
        else
        {
            return new CertPathValidationResult(context,
                toInts(certIndexes), toInts(ruleIndexes), (CertPathValidationException[])exceptions.toArray(new CertPathValidationException[exceptions.size()]));
        }
    }

    public void addException(int certIndex, int ruleIndex, CertPathValidationException exception)
    {
        this.certIndexes.add(Integers.valueOf(certIndex));
        this.ruleIndexes.add(Integers.valueOf(ruleIndex));
        this.exceptions.add(exception);
    }

    private int[] toInts(List<Integer> values)
    {
        int[] rv = new int[values.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = ((Integer)values.get(i)).intValue();
        }

        return rv;
    }
}
