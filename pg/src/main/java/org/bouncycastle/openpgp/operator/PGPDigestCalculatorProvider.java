package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PGPDigestCalculatorProvider
{
    PGPDigestCalculator get(int algorithm)
        throws PGPException;
}
