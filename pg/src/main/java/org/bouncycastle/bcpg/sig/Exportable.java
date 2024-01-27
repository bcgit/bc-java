package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Booleans;

/**
 * Signature subpacket indicating, whether the carrying signature is intended to be exportable.
 */
public class Exportable 
    extends SignatureSubpacket
{
    public Exportable(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EXPORTABLE, critical, isLongLength, data);
    }
    
    public Exportable(
        boolean    critical,
        boolean    isExportable)
    {
        super(SignatureSubpacketTags.EXPORTABLE, critical, false, Booleans.toByteArray(isExportable));
    }
    
    public boolean isExportable()
    {
        return Booleans.fromByteArray(data);
    }
}
