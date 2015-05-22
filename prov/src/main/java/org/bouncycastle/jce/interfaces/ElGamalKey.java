package org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
