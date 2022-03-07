package org.bouncycastle.oer;

/**
 * Element suppliers allow us to defer the finalisation of a definition until
 * the point at which it is used.
 */
public interface ElementSupplier
{
    Element build();
}
