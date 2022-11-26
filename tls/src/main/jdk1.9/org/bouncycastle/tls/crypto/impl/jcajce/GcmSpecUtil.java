package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.util.Integers;

class GcmSpecUtil
{
    static boolean gcmSpecExists()
    {
        return true;
    }

    static AlgorithmParameterSpec createGcmSpec(byte[] nonce, int macLen)
        throws InvalidParameterSpecException
    {
        return new GCMParameterSpec(macLen * 8, nonce);
    }
}
