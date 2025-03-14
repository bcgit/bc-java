package org.bouncycastle.jcajce.provider.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.util.Integers;

public class SecretKeyUtil
{
    private static Map<ASN1ObjectIdentifier, Integer> keySizes = new HashMap<>();

    static
    {
        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC, 192);

        keySizes.put(NISTObjectIdentifiers.id_aes128_CBC, 128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CBC, 192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CBC, 256);

        keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc, 128);
        keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc, 192);
        keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc, 256);
    }

    public static int getKeySize(ASN1ObjectIdentifier oid)
    {
        Integer size = keySizes.get(oid);

        if (size != null)
        {
            return size;
        }

        return -1;
    }
}
