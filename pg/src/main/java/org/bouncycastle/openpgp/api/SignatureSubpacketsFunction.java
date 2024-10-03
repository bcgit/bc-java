package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

/**
 * Callback to modify the contents of a {@link PGPSignatureSubpacketGenerator}.
 */
@FunctionalInterface
public interface SignatureSubpacketsFunction {
    /**
     * Apply some changes to the given {@link PGPSignatureSubpacketGenerator} and return the result.
     * It is also possible to replace the whole {@link PGPSignatureSubpacketGenerator} by returning another instance.
     *
     * @param subpackets original subpackets
     * @return modified subpackets
     */
    PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets);
}
