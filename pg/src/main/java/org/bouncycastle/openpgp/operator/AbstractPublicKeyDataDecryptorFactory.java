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
}
