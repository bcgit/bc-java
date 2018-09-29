package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;

/**
 * Base interface for a qTESLA key.
 */
public interface QTESLAKey
{
    /**
     * Return the parameters for this key - in this case the security category.
     *
     * @return a QTESLAParameterSpec
     */
    QTESLAParameterSpec getParams();
}
