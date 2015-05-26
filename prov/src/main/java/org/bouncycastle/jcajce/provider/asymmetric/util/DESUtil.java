package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.Strings;

public class DESUtil
{
    private static final Set<String> des = new HashSet<String>();

    static
    {
        des.add("DES");
        des.add("DESEDE");
        des.add(OIWObjectIdentifiers.desCBC.getId());
        des.add(PKCSObjectIdentifiers.des_EDE3_CBC.getId());
        des.add(PKCSObjectIdentifiers.des_EDE3_CBC.getId());
        des.add(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());
    }

    public static boolean isDES(String algorithmID)
    {
        String name = Strings.toUpperCase(algorithmID);

        return des.contains(name);
    }

    /**
     * DES Keys use the LSB as the odd parity bit.  This can
     * be used to check for corrupt keys.
     *
     * @param bytes the byte array to set the parity on.
     */
    public static void setOddParity(
        byte[] bytes)
    {
        for (int i = 0; i < bytes.length; i++)
        {
            int b = bytes[i];
            bytes[i] = (byte)((b & 0xfe) |
                            ((((b >> 1) ^
                            (b >> 2) ^
                            (b >> 3) ^
                            (b >> 4) ^
                            (b >> 5) ^
                            (b >> 6) ^
                            (b >> 7)) ^ 0x01) & 0x01));
        }
    }
}
