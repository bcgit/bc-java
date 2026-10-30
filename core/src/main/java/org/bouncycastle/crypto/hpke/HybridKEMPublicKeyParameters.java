package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Public (encapsulation) key of one of the ML-KEM / NIST curve hybrid KEMs of
 * draft-irtf-cfrg-concrete-hybrid-kems used with HPKE ({@link HPKE#kem_MLKEM768_P256},
 * {@link HPKE#kem_MLKEM1024_P384}): the ML-KEM encapsulation key followed by the
 * uncompressed curve point, which is also its serialized form.
 */
public class HybridKEMPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final short kemId;
    private final byte[] encoded;

    HybridKEMPublicKeyParameters(short kemId, byte[] encoded)
    {
        super(false);

        this.kemId = kemId;
        this.encoded = Arrays.clone(encoded);
    }

    public short getKemId()
    {
        return kemId;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }
}
