package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Arrays;

public abstract class AbstractPublicKeyDataDecryptorFactory
        implements PublicKeyDataDecryptorFactory
{
    @Override
    public final byte[] recoverSessionData(PublicKeyEncSessionPacket pkesk, InputStreamPacket encData)
            throws PGPException
    {
        byte[] sessionData = recoverSessionData(pkesk.getAlgorithm(), pkesk.getEncSessionKey(), pkesk.getVersion());
        return prependSKAlgorithmToSessionData(pkesk, encData, sessionData);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        return recoverSessionData(keyAlgorithm, secKeyData, PublicKeyEncSessionPacket.VERSION_3);
    }

    protected byte[] prependSKAlgorithmToSessionData(PublicKeyEncSessionPacket pkesk,
                                                   InputStreamPacket encData,
                                                   byte[] decryptedSessionData)
            throws PGPException
    {
        // V6 PKESK packets do not include the session key algorithm, so source it from the SEIPD2 instead
        if (!containsSKAlg(pkesk.getVersion()))
        {
            if (!(encData instanceof SymmetricEncIntegrityPacket) ||
                    ((SymmetricEncIntegrityPacket) encData).getVersion() != SymmetricEncIntegrityPacket.VERSION_2)
            {
                throw new PGPException("v6 PKESK packet MUST precede v2 SEIPD packet");
            }

            SymmetricEncIntegrityPacket seipd2 = (SymmetricEncIntegrityPacket) encData;
            return Arrays.prepend(decryptedSessionData,
                    (byte) (seipd2.getCipherAlgorithm() & 0xff));
        }
        // V3 PKESK does store the session key algorithm either encrypted or unencrypted, depending on the PK algorithm
        else
        {
            switch (pkesk.getAlgorithm())
            {
                case PublicKeyAlgorithmTags.X25519:
                    // X25519 does not encrypt SK algorithm
                    return Arrays.prepend(decryptedSessionData,
                            pkesk.getEncSessionKey()[0][X25519PublicBCPGKey.LENGTH + 1]);
                case PublicKeyAlgorithmTags.X448:
                    // X448 does not encrypt SK algorithm
                    return Arrays.prepend(decryptedSessionData,
                            pkesk.getEncSessionKey()[0][X448PublicBCPGKey.LENGTH + 1]);
                default:
                    // others already prepended session key algorithm to session key
                    return decryptedSessionData;
            }
        }
    }

    protected boolean containsSKAlg(int pkeskVersion)
    {
        return pkeskVersion != PublicKeyEncSessionPacket.VERSION_6;
    }

    protected static void checkRange(int pLen, byte[] enc)
            throws PGPException
    {
        if (pLen > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }
    }

    /**
     * Parse the algorithm-specific encrypted-session-key field of an X25519 or X448 PKESK packet
     * into the sender's ephemeral public key and the wrapped session key, applying all length
     * checks. Shared so every decryptor factory applies exactly the same checks.
     *
     * @param enc the PKESK's encrypted session key data
     * @param pLen length in octets of the ephemeral public key (32 for X25519, 56 for X448)
     * @param containsSKAlg whether the packet version carries the symmetric-key algorithm octet (v3)
     * @return a two-element array of the ephemeral public key and the wrapped session key
     * @throws PGPException if the data is shorter than its declared lengths require
     */
    protected static byte[][] parseXDHEncSessionKey(byte[] enc, int pLen, boolean containsSKAlg)
            throws PGPException
    {
        // ephemeral key (32 / 56 octets)
        byte[] ephemeralKey = Arrays.copyOf(enc, pLen);

        // size of following fields
        checkRange(pLen + 1, enc);
        int size = enc[pLen] & 0xff;
        checkRange(pLen + 1 + size, enc);

        if (containsSKAlg && size < 1)
        {
            // a v3 PKESK's size octet covers the symmetric algorithm octet plus the wrapped key, so a
            // declared size of zero leaves no room for it - guard before the length arithmetic underflows
            throw new PGPException("encoded length out of range");
        }

        // encrypted session key
        int sesKeyLen = size - (containsSKAlg ? 1 : 0);
        int sesKeyOff = pLen + 1 + (containsSKAlg ? 1 : 0);

        return new byte[][]{ ephemeralKey, Arrays.copyOfRange(enc, sesKeyOff, sesKeyOff + sesKeyLen) };
    }

    /**
     * Parse the encrypted-session-key field of an ECDH (RFC 6637) PKESK packet into the sender's
     * MPI-encoded ephemeral point and the wrapped session key, applying all length checks. Shared
     * so every decryptor factory applies exactly the same checks.
     *
     * @param enc the PKESK's encrypted session key data
     * @return a two-element array of the encoded ephemeral point and the wrapped session key
     * @throws PGPException if the data is shorter than its declared lengths require
     */
    protected static byte[][] parseECDHEncSessionKey(byte[] enc)
            throws PGPException
    {
        // the two length octets themselves
        checkRange(2, enc);
        int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
        checkRange(2 + pLen + 1, enc);

        byte[] pEnc = new byte[pLen];
        System.arraycopy(enc, 2, pEnc, 0, pLen);

        int keyLen = enc[pLen + 2] & 0xff;
        checkRange(2 + pLen + 1 + keyLen, enc);

        byte[] keyEnc = new byte[keyLen];
        System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

        return new byte[][]{ pEnc, keyEnc };
    }
}
