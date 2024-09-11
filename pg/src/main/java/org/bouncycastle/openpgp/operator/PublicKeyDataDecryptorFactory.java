package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    /**
     * Recover the plain session info by decrypting the encrypted session key.
     * The session info ALWAYS has the symmetric algorithm ID prefixed, so the return value is:
     * <pre>[sym-alg][session-key][checksum]?</pre>
     *
     * @param pkesk public-key encrypted session-key packet
     * @param encData encrypted data (sed/seipd/oed) packet
     * @return decrypted session info
     * @throws PGPException
     */
    byte[] recoverSessionData(PublicKeyEncSessionPacket pkesk, InputStreamPacket encData)
            throws PGPException;

    /**
     * Recover the plain session info by decrypting the encrypted session key.
     * This method returns the decrypted session info as-is (without prefixing missing cipher algorithm),
     * so the return value is:
     * <pre>[sym-alg]?[session-key][checksum]?</pre>
     *
     * @deprecated use {@link #recoverSessionData(PublicKeyEncSessionPacket, InputStreamPacket)} instead.
     * @param keyAlgorithm public key algorithm
     * @param secKeyData encrypted session key data
     * @return decrypted session info
     * @throws PGPException
     */
    byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException;

    /**
     * Recover the plain session info by decrypting the encrypted session key.
     * This method returns the decrypted session info as-is (without prefixing missing cipher algorithm),
     * so the return value is:
     * <pre>[sym-alg]?[session-key][checksum]?</pre>
     *
     * @deprecated use {@link #recoverSessionData(PublicKeyEncSessionPacket, InputStreamPacket)} instead.
     * @param keyAlgorithm public key algorithm
     * @param secKeyData encrypted session key data
     * @param pkeskVersion version of the PKESK packet
     * @return decrypted session info
     * @throws PGPException
     */
    byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
            throws PGPException;

}
