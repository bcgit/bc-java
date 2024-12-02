package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

/**
 * Callback to modify the contents of a {@link PGPSignatureSubpacketGenerator}.
 * The {@link OpenPGPV6KeyGenerator} already prepopulates the hashed subpacket areas of signatures during
 * key generation. This callback is useful to apply custom changes to the hashed subpacket area during the
 * generation process.
 */
@FunctionalInterface
public interface SignatureSubpacketsFunction
{
    /**
     * Apply some changes to the given {@link PGPSignatureSubpacketGenerator} and return the result.
     * It is also possible to replace the whole {@link PGPSignatureSubpacketGenerator} by returning another instance.
     * Tipp: In order to replace a subpacket, make sure to prevent duplicates by first removing subpackets
     * of the same type using {@link PGPSignatureSubpacketGenerator#removePacketsOfType(int)}.
     * To inspect the current contents of the generator, it is best to call
     * {@link PGPSignatureSubpacketGenerator#generate()} and in turn inspect its contents using
     * {@link PGPSignatureSubpacketVector#toArray()}.
     *
     * @param subpackets original subpackets
     * @return non-null modified subpackets
     */
    PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets);
}
