package org.bouncycastle.its.operator;

import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;

public interface ETSIDataVerifierProvider
{
    public ContentVerifier getContentVerifier(int signatureChoice)
        throws OperatorCreationException;
}
