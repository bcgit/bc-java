package org.bouncycastle.jsse.java.security;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;

public interface BCAlgorithmConstraints
{
    boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters);

    boolean permits(Set<BCCryptoPrimitive> primitives, Key key);

    boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters);
}
