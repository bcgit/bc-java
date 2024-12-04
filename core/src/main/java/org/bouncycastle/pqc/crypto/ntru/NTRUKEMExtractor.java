package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/**
 * NTRU secret encapsulation extractor.
 */
public class NTRUKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final NTRUPrivateKeyParameters ntruPrivateKey;

    /**
     * Constructor.
     * an NTRU parameter
     *
     * @param ntruPrivateKey private key used to encapsulate the secret
     */
    public NTRUKEMExtractor(NTRUPrivateKeyParameters ntruPrivateKey)
    {
        if (ntruPrivateKey == null)
        {
            throw new NullPointerException("'ntruPrivateKey' cannot be null");
        }

        this.ntruPrivateKey = ntruPrivateKey;
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        NTRUParameterSet parameterSet = ntruPrivateKey.getParameters().getParameterSet();

        if (encapsulation == null)
        {
            throw new NullPointerException("'encapsulation' cannot be null");
        }
        if (encapsulation.length != parameterSet.ntruCiphertextBytes())
        {
            throw new IllegalArgumentException("encapsulation");
        }

        byte[] sk = this.ntruPrivateKey.privateKey;

        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        OWCPADecryptResult owcpaResult = owcpa.decrypt(encapsulation, sk);
        byte[] rm = owcpaResult.rm;
        int fail = owcpaResult.fail;
        /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
        /* See comment in owcpa_dec for details.                                */

        SHA3Digest sha3256 = new SHA3Digest(256);
        byte[] k = new byte[sha3256.getDigestSize()];

        sha3256.update(rm, 0, rm.length);
        sha3256.doFinal(k, 0);

        /* shake(secret PRF key || input ciphertext) */
        sha3256.update(sk, parameterSet.owcpaSecretKeyBytes(), parameterSet.prfKeyBytes());
        sha3256.update(encapsulation, 0, encapsulation.length);
        sha3256.doFinal(rm, 0);

        cmov(k, rm, (byte)fail);

        byte[] sharedKey = Arrays.copyOfRange(k, 0, parameterSet.sharedKeyBytes());
        Arrays.clear(k);

        return sharedKey;
    }

    private void cmov(byte[] r, byte[] x, byte b)
    {
        b = (byte)(~b + 1);
        for (int i = 0; i < r.length; i++)
        {
            r[i] ^= b & (x[i] ^ r[i]);
        }
    }

    public int getEncapsulationLength()
    {
        return ntruPrivateKey.getParameters().getParameterSet().ntruCiphertextBytes();
    }
}
