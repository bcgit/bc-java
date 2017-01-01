package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.x509.Extension;

class Utils
{
    static BodyPartID[] clone(BodyPartID[] ids)
    {
        BodyPartID[] tmp = new BodyPartID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }

    static Extension[] clone(Extension[] ids)
    {
        Extension[] tmp = new Extension[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }
}
