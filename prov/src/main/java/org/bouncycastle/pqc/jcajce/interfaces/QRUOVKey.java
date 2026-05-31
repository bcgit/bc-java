package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;

public interface QRUOVKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a QRUOVParameterSpec
     */
    QRUOVParameterSpec getParameterSpec();
}
