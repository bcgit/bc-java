package org.bouncycastle.openpgp.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Byte-level building blocks of the ML-KEM + ECDH composite encryption schemes of RFC 9980 that are shared by
 * the lightweight (<code>.bc</code>) and JCA (<code>.jcajce</code>) operators: the key combiner of sec. 4.2.1
 * and the PKESK algorithm-specific field layout of sec. 4.3.1. The composite signature schemes need no such
 * helpers - their signatures are the plain concatenation of the two component signatures.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4">
 *     RFC 9980 - Composite KEM Schemes</a>
 */
public class RFC9980Utils
{
    /**
     * The domain separation constant of the key combiner (RFC 9980 sec. 4.2.1): the UTF-8 encoding of
     * "OpenPGPCompositeKDFv1".
     */
    public static final byte[] DOM_SEP = Strings.toByteArray("OpenPGPCompositeKDFv1");

    /**
     * The symmetric algorithm the composite schemes wrap the session key with (RFC 9980 sec. 4.2):
     * AES-256 key wrap as per RFC 3394.
     */
    public static final int KEY_WRAP_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;

    private RFC9980Utils()
    {
    }

    /**
     * Compute the key encryption key of the composite scheme (RFC 9980 sec. 4.2.1):
     * <pre>
     * KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey || algId || domSep || len(domSep))
     * </pre>
     *
     * @param sha3_256 a fresh digest calculator for {@link HashAlgorithmTags#SHA3_256}
     * @param mlkemKeyShare the ML-KEM key share (shared secret key) as an octet string
     * @param ecdhKeyShare the ECDH key share as an octet string
     * @param ecdhCipherText the ECDH ciphertext (the ephemeral public key) as an octet string
     * @param ecdhPublicKey the ECDH public key of the recipient as an octet string
     * @param algorithmId the OpenPGP algorithm ID of the public key encryption algorithm
     * @return the 32 octet KEK
     * @throws PGPException if the digest calculator is not SHA3-256 or the KEK cannot be computed
     */
    public static byte[] deriveKEK(PGPDigestCalculator sha3_256, byte[] mlkemKeyShare, byte[] ecdhKeyShare,
                                   byte[] ecdhCipherText, byte[] ecdhPublicKey, int algorithmId)
        throws PGPException
    {
        if (sha3_256.getAlgorithm() != HashAlgorithmTags.SHA3_256)
        {
            throw new PGPException("RFC 9980 key combiner requires SHA3-256, got hash algorithm " + sha3_256.getAlgorithm());
        }
        if (!PublicKeyUtils.isMLKEMCompositeAlgorithm(algorithmId))
        {
            throw new PGPException("not an ML-KEM composite algorithm: " + algorithmId);
        }

        try
        {
            OutputStream out = sha3_256.getOutputStream();
            out.write(mlkemKeyShare);
            out.write(ecdhKeyShare);
            out.write(ecdhCipherText);
            out.write(ecdhPublicKey);
            out.write(algorithmId);
            out.write(DOM_SEP);
            out.write(DOM_SEP.length);
            out.close();
        }
        catch (IOException e)
        {
            throw new PGPException("cannot compute RFC 9980 KEK: " + e.getMessage(), e);
        }

        return sha3_256.getDigest();
    }

    /**
     * Return true if the symmetric algorithm may be named by a v3 PKESK packet of a composite scheme.
     * RFC 9980 sec. 4.3.1 restricts it to AES-128, AES-192 and AES-256.
     *
     * @param symmetricKeyAlgorithm symmetric key algorithm ID
     * @return true for the three AES key sizes
     */
    public static boolean isAllowedV3PKESKSymmetricAlgorithm(int symmetricKeyAlgorithm)
    {
        return symmetricKeyAlgorithm == SymmetricKeyAlgorithmTags.AES_128
            || symmetricKeyAlgorithm == SymmetricKeyAlgorithmTags.AES_192
            || symmetricKeyAlgorithm == SymmetricKeyAlgorithmTags.AES_256;
    }

    /**
     * Check that a session key unwrapped from a v3 PKESK packet of a composite scheme is consistent with the
     * symmetric algorithm octet the packet carries in the clear: the algorithm MUST be an AES variant and the
     * key length MUST match it (RFC 9980 sec. 4.3.1).
     *
     * @param symmetricKeyAlgorithm symmetric key algorithm ID from the PKESK packet
     * @param sessionKey the unwrapped session key
     * @throws PGPException if the algorithm is not AES or the key length does not match it
     */
    public static void checkV3SessionKey(int symmetricKeyAlgorithm, byte[] sessionKey)
        throws PGPException
    {
        if (!isAllowedV3PKESKSymmetricAlgorithm(symmetricKeyAlgorithm))
        {
            throw new PGPException("v3 PKESK packet of an ML-KEM composite scheme MUST use AES-128, AES-192 or AES-256, got symmetric algorithm "
                + symmetricKeyAlgorithm);
        }
        if (sessionKey.length != SymmetricKeyUtils.getKeyLengthInOctets(symmetricKeyAlgorithm))
        {
            throw new PGPException("unwrapped session key length (" + sessionKey.length
                + ") does not match symmetric algorithm " + symmetricKeyAlgorithm);
        }
    }

    /**
     * Parse the algorithm-specific field of a PKESK packet of a composite scheme (RFC 9980 sec. 4.3.1):
     * <pre>
     * ecdhCipherText || mlkemCipherText || len(C, symAlgId) (|| symAlgId) || C
     * </pre>
     * where the one-octet symAlgId is present only in a v3 packet.
     *
     * @param enc the PKESK's encrypted session key data
     * @param algorithmId the public key algorithm ID of the packet, which fixes the two ciphertext lengths
     * @param containsSKAlg whether the packet version carries the symmetric-key algorithm octet (v3)
     * @return a four-element array of the ECDH ciphertext, the ML-KEM ciphertext, the wrapped session key C,
     * and the symmetric algorithm octet (a one-element array for a v3 packet, empty otherwise)
     * @throws PGPException if the data is shorter than its declared lengths require
     */
    public static byte[][] parseEncryptedSessionKey(byte[] enc, int algorithmId, boolean containsSKAlg)
        throws PGPException
    {
        if (!PublicKeyUtils.isMLKEMCompositeAlgorithm(algorithmId))
        {
            throw new PGPException("not an ML-KEM composite algorithm: " + algorithmId);
        }

        int ecdhLen = MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(algorithmId);
        int mlkemLen = MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(algorithmId);

        // the two ciphertexts and the size octet
        checkRange(ecdhLen + mlkemLen + 1, enc);
        int size = enc[ecdhLen + mlkemLen] & 0xff;
        checkRange(ecdhLen + mlkemLen + 1 + size, enc);

        if (containsSKAlg && size < 1)
        {
            // the v3 size octet covers the symmetric algorithm octet plus the wrapped key, so a declared
            // size of zero leaves no room for it
            throw new PGPException("encoded length out of range");
        }

        byte[] ecdhCipherText = Arrays.copyOfRange(enc, 0, ecdhLen);
        byte[] mlkemCipherText = Arrays.copyOfRange(enc, ecdhLen, ecdhLen + mlkemLen);

        int wrappedOff = ecdhLen + mlkemLen + 1 + (containsSKAlg ? 1 : 0);
        int wrappedLen = size - (containsSKAlg ? 1 : 0);
        byte[] wrapped = Arrays.copyOfRange(enc, wrappedOff, wrappedOff + wrappedLen);

        byte[] symAlg = containsSKAlg ? new byte[]{ enc[ecdhLen + mlkemLen + 1] } : new byte[0];

        return new byte[][]{ ecdhCipherText, mlkemCipherText, wrapped, symAlg };
    }

    /**
     * Return the offset of the symmetric algorithm octet in the algorithm-specific field of a v3 PKESK packet
     * of a composite scheme: just past the two ciphertexts and the size octet.
     *
     * @param algorithmId the public key algorithm ID of the packet
     * @return offset of the symmetric algorithm octet
     */
    public static int getV3SymmetricAlgorithmOffset(int algorithmId)
    {
        return MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(algorithmId)
            + MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(algorithmId) + 1;
    }

    private static void checkRange(int len, byte[] enc)
        throws PGPException
    {
        if (len > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }
    }
}
