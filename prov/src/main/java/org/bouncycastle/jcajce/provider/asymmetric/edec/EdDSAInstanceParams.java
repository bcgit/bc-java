package org.bouncycastle.jcajce.provider.asymmetric.edec;

/**
 * Carrier for the RFC 8032 instance selectors (prehash / context) extracted from an
 * AlgorithmParameterSpec by {@link EdDSAKeys#getInstanceParams}, independent of which spec
 * class delivered them - the BC {@link org.bouncycastle.jcajce.spec.EdDSAParameterSpec}, or
 * on JDK 15+ the standard {@code java.security.spec.EdDSAParameterSpec}, which carries no
 * curve name.
 */
class EdDSAInstanceParams
{
    final String curveName;     // null when the spec does not name a curve
    final boolean prehash;
    final byte[] context;       // null for none

    EdDSAInstanceParams(String curveName, boolean prehash, byte[] context)
    {
        this.curveName = curveName;
        this.prehash = prehash;
        this.context = context;
    }
}
