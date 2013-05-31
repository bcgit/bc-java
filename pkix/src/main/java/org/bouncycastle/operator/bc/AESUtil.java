package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.KeyParameter;

class AESUtil
{
    static AlgorithmIdentifier determineKeyEncAlg(KeyParameter key)
    {
        int length = key.getKey().length * 8;
        ASN1ObjectIdentifier wrapOid;

        if (length == 128)
        {
            wrapOid = NISTObjectIdentifiers.id_aes128_wrap;
        }
        else if (length == 192)
        {
            wrapOid = NISTObjectIdentifiers.id_aes192_wrap;
        }
        else if (length == 256)
        {
            wrapOid = NISTObjectIdentifiers.id_aes256_wrap;
        }
        else
        {
            throw new IllegalArgumentException("illegal keysize in AES");
        }

        return new AlgorithmIdentifier(wrapOid); // parameters absent
    }
}
