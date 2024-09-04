package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket for marking a signature as exportable or non-exportable.
 * Non-exportable signatures are not intended to be published.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.11">
 *     RFC4880 - Exportable Certification</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification">
 *     RFC9580 - Exportable Certification</a>
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
        super(SignatureSubpacketTags.EXPORTABLE, critical, false,  Utils.booleanToByteArray(isExportable));
    }
    
    public boolean isExportable()
    {
        return Utils.booleanFromByteArray(data);
    }
}
