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
    private final NTRUParameters params;
    private final NTRUPrivateKeyParameters ntruPrivateKey;

    /**
     * Constructor.
     * an NTRU parameter
     *
     * @param ntruPrivateKey private key used to encapsulate the secret
     */
    public NTRUKEMExtractor(NTRUPrivateKeyParameters ntruPrivateKey)
    {
        this.params = ntruPrivateKey.getParameters();
        this.ntruPrivateKey = ntruPrivateKey;
    }


    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
//        assert this.ntruPrivateKey != null;
        NTRUParameterSet parameterSet = this.params.parameterSet;

        byte[] sk = this.ntruPrivateKey.privateKey;
        int i, fail;
        byte[] rm;
        byte[] buf = new byte[parameterSet.prfKeyBytes() + parameterSet.ntruCiphertextBytes()];

        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        OWCPADecryptResult owcpaResult = owcpa.decrypt(encapsulation, ntruPrivateKey.privateKey);
        rm = owcpaResult.rm;
        fail = owcpaResult.fail;
        /* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
        /* See comment in owcpa_dec for details.                                */

        SHA3Digest sha3256 = new SHA3Digest(256);

        byte[] k = new byte[sha3256.getDigestSize()];

        sha3256.update(rm, 0, rm.length);
        sha3256.doFinal(k, 0);

        /* shake(secret PRF key || input ciphertext) */
        for (i = 0; i < parameterSet.prfKeyBytes(); i++)
        {
            buf[i] = sk[i + parameterSet.owcpaSecretKeyBytes()];
        }
        for (i = 0; i < parameterSet.ntruCiphertextBytes(); i++)
        {
            buf[parameterSet.prfKeyBytes() + i] = encapsulation[i];
        }
        sha3256.reset();
        sha3256.update(buf, 0, buf.length);
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
        return params.parameterSet.ntruCiphertextBytes();
    }
}
