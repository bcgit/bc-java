package com.github.gv2011.bcasn.util.io.pem;

/**
 * Base interface for generators of PEM objects.
 */
public interface PemObjectGenerator
{
    /**
     * Generate a PEM object.
     *
     * @return the generated object.
     * @throws PemGenerationException on failure.
     */
    PemObject generate()
        throws PemGenerationException;
}
