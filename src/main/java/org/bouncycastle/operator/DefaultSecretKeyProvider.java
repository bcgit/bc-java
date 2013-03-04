package org.bouncycastle.operator;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Integers;

public class DefaultSecretKeyProvider
    implements SecretKeySizeProvider
{
    public static final SecretKeySizeProvider INSTANCE = new DefaultSecretKeyProvider();

    private static final Map KEY_SIZES;

    static
    {
        Map keySizes = new HashMap();

        keySizes.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));

        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(192));

        keySizes.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
        keySizes.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
        keySizes.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));

        keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
        keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
        keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));

        KEY_SIZES = Collections.unmodifiableMap(keySizes);
    }

    public int getKeySize(AlgorithmIdentifier algorithmIdentifier)
    {
        // TODO: not all ciphers/oid relationships are this simple.
        Integer keySize = (Integer)KEY_SIZES.get(algorithmIdentifier.getAlgorithm());

        if (keySize != null)
        {
            return keySize.intValue();
        }

        return -1;
    }


}
