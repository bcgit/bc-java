package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

public interface LMSKey
    extends Key
{
    int getLevels();
}
