package org.bouncycastle.cert.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.util.Exceptions;

/**
 * RFC 6962 (CT v1) {@code SignedCertificateTimestampList}: the TLS-encoded
 * structure carried inside the embedded-SCT certificate extension and the
 * OCSP SCT-list extension.
 *
 * <pre>
 *     opaque SerializedSCT&lt;1..2^16-1&gt;;
 *
 *     struct {
 *         SerializedSCT sct_list&lt;1..2^16-1&gt;;
 *     } SignedCertificateTimestampList;
 * </pre>
 *
 * The list bytes — i.e. what this class consumes — are the unwrapped
 * contents of the extension's OCTET STRING value (the bytes returned by
 * {@code Extension.getExtnValue().getOctets()}), not the OCTET STRING
 * header itself.
 *
 * <p>For RFC 9162 (CT v2), the analogous list type is
 * {@link TransItemList}; the two formats are not interchangeable.</p>
 *
 * @see X509ObjectIdentifiers#id_ce_ct_embeddedSCTList
 * @see X509ObjectIdentifiers#id_ocsp_ct_sctList
 */
public class SignedCertificateTimestampList
{
    private final List/*<SignedCertificateTimestamp>*/ scts;

    public SignedCertificateTimestampList(SignedCertificateTimestamp[] scts)
    {
        if (scts == null)
        {
            throw new NullPointerException("'scts' cannot be null");
        }
        if (scts.length == 0)
        {
            throw new IllegalArgumentException("SignedCertificateTimestampList must contain at least one SCT");
        }

        List collected = new ArrayList(scts.length);
        for (int i = 0; i != scts.length; i++)
        {
            if (scts[i] == null)
            {
                throw new NullPointerException("scts[" + i + "] is null");
            }
            collected.add(scts[i]);
        }
        this.scts = Collections.unmodifiableList(collected);
    }

    /**
     * Decode a list from its TLS wire form (the bytes of the extension
     * value's OCTET STRING contents).
     */
    public static SignedCertificateTimestampList getInstance(byte[] encoded)
    {
        CTByteReader outer = new CTByteReader(encoded);
        int listLen = outer.readU16();
        if (listLen != outer.remaining())
        {
            throw new IllegalArgumentException(
                "SignedCertificateTimestampList declared length " + listLen
                    + " does not match remaining " + outer.remaining() + " bytes");
        }

        List/*<SignedCertificateTimestamp>*/ items = new ArrayList();
        while (outer.remaining() > 0)
        {
            int sctLen = outer.readU16();
            byte[] sctBytes = outer.readBytes(sctLen);
            items.add(SignedCertificateTimestamp.getInstance(sctBytes));
        }

        return new SignedCertificateTimestampList(
            (SignedCertificateTimestamp[])items.toArray(new SignedCertificateTimestamp[items.size()]));
    }

    /**
     * Recover the v1 SCT list from the {@link X509ObjectIdentifiers#id_ce_ct_embeddedSCTList}
     * certificate extension, if present. Returns {@code null} when the
     * extension is absent.
     */
    public static SignedCertificateTimestampList fromExtensions(Extensions extensions)
    {
        if (extensions == null)
        {
            return null;
        }
        Extension ext = extensions.getExtension(X509ObjectIdentifiers.id_ce_ct_embeddedSCTList);
        if (ext == null)
        {
            return null;
        }

        ASN1OctetString extnValue = ext.getExtnValue();
        return getInstance(extnValue.getOctets());
    }

    /** The decoded SCTs, in wire order. */
    public List getSCTs()
    {
        return scts;
    }

    public int size()
    {
        return scts.size();
    }

    /**
     * Serialize the list to its TLS wire form (the bytes that would be
     * carried as the OCTET STRING contents of the embedded-SCT or OCSP-SCT
     * extension's extnValue).
     */
    public byte[] getEncoded()
    {
        ByteArrayOutputStream listBody = new ByteArrayOutputStream();
        try
        {
            for (int i = 0; i != scts.size(); i++)
            {
                SignedCertificateTimestamp sct = (SignedCertificateTimestamp)scts.get(i);
                byte[] sctBytes = sct.getEncoded();
                CTByteWriter w = new CTByteWriter(listBody);
                w.writeOpaqueU16(sctBytes);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            CTByteWriter w = new CTByteWriter(out);
            w.writeOpaqueU16(listBody.toByteArray());
            return out.toByteArray();
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
}
