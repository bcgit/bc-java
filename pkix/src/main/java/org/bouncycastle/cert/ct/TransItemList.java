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
 * RFC 9162 (CT v2) {@code TransItemList}: the TLS-encoded structure carried
 * inside the Transparency Information X.509v3 extension
 * ({@link X509ObjectIdentifiers#id_ce_ct_transparencyInformation}).
 *
 * <pre>
 *     opaque SerializedTransItem&lt;1..2^16-1&gt;;
 *
 *     struct {
 *         SerializedTransItem trans_item_list&lt;1..2^16-1&gt;;
 *     } TransItemList;
 * </pre>
 *
 * The list bytes — i.e. what this class consumes — are the unwrapped
 * contents of the extension's OCTET STRING value, not the OCTET STRING
 * header itself.
 *
 * <p>For RFC 6962 (CT v1), the analogous list type is
 * {@link SignedCertificateTimestampList}; the two formats are not
 * interchangeable.</p>
 */
public class TransItemList
{
    private final List/*<TransItem>*/ items;

    public TransItemList(TransItem[] items)
    {
        if (items == null)
        {
            throw new NullPointerException("'items' cannot be null");
        }
        if (items.length == 0)
        {
            throw new IllegalArgumentException("TransItemList must contain at least one item");
        }

        List collected = new ArrayList(items.length);
        for (int i = 0; i != items.length; i++)
        {
            if (items[i] == null)
            {
                throw new NullPointerException("items[" + i + "] is null");
            }
            collected.add(items[i]);
        }
        this.items = Collections.unmodifiableList(collected);
    }

    public static TransItemList getInstance(byte[] encoded)
    {
        CTByteReader outer = new CTByteReader(encoded);
        int listLen = outer.readU16();
        if (listLen != outer.remaining())
        {
            throw new IllegalArgumentException(
                "TransItemList declared length " + listLen
                    + " does not match remaining " + outer.remaining() + " bytes");
        }

        List/*<TransItem>*/ items = new ArrayList();
        while (outer.remaining() > 0)
        {
            int itemLen = outer.readU16();
            byte[] itemBytes = outer.readBytes(itemLen);
            items.add(TransItem.getInstance(itemBytes));
        }

        return new TransItemList((TransItem[])items.toArray(new TransItem[items.size()]));
    }

    /**
     * Recover the v2 TransItem list from the
     * {@link X509ObjectIdentifiers#id_ce_ct_transparencyInformation}
     * certificate extension, if present. Returns {@code null} when the
     * extension is absent.
     */
    public static TransItemList fromExtensions(Extensions extensions)
    {
        if (extensions == null)
        {
            return null;
        }
        Extension ext = extensions.getExtension(X509ObjectIdentifiers.id_ce_ct_transparencyInformation);
        if (ext == null)
        {
            return null;
        }

        ASN1OctetString extnValue = ext.getExtnValue();
        return getInstance(extnValue.getOctets());
    }

    /** The decoded TransItems, in wire order. */
    public List getItems()
    {
        return items;
    }

    public int size()
    {
        return items.size();
    }

    public byte[] getEncoded()
    {
        ByteArrayOutputStream listBody = new ByteArrayOutputStream();
        try
        {
            for (int i = 0; i != items.size(); i++)
            {
                TransItem item = (TransItem)items.get(i);
                byte[] itemBytes = item.getEncoded();
                CTByteWriter w = new CTByteWriter(listBody);
                w.writeOpaqueU16(itemBytes);
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
