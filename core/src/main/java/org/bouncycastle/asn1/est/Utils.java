package org.bouncycastle.asn1.est;

/**
 * @deprecated use org.bouncycastle.est.asn1.Utils
 */
class Utils
{
    static AttrOrOID[] clone(AttrOrOID[] ids)
    {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }
}
