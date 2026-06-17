package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.cms.CMSEncryptedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.InputDecryptorProvider;

/**
 * Factory that materialises the {@link PKCS12SafeBag}s carried in one {@link ContentInfo} of a
 * PFX's AuthenticatedSafe. Use the single-argument constructor for plain {@code data} content
 * infos and the two-argument constructor with an {@link InputDecryptorProvider} for
 * {@code encryptedData} content infos.
 */
public class PKCS12SafeBagFactory
{
    private ASN1Sequence safeBagSeq;

    /**
     * Construct a factory over a plain (unencrypted) {@code data} ContentInfo.
     *
     * @param info the ContentInfo holding the SafeContents.
     * @throws IllegalArgumentException if {@code info} is an {@code encryptedData} ContentInfo.
     */
    public PKCS12SafeBagFactory(ContentInfo info)
    {
        if (info.getContentType().equals(PKCSObjectIdentifiers.encryptedData))
        {
            throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
        }

        this.safeBagSeq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(info.getContent()).getOctets());
    }

    /**
     * Construct a factory over an {@code encryptedData} ContentInfo, decrypting its contents
     * with the supplied provider.
     *
     * @param info                   the encrypted ContentInfo.
     * @param inputDecryptorProvider provider able to produce a decryptor matching the
     *                               algorithm identifier carried by {@code info}.
     * @throws PKCSException if decryption fails.
     * @throws IllegalArgumentException if {@code info} is not an {@code encryptedData} ContentInfo.
     */
    public PKCS12SafeBagFactory(ContentInfo info, InputDecryptorProvider inputDecryptorProvider)
        throws PKCSException
    {
        if (info.getContentType().equals(PKCSObjectIdentifiers.encryptedData))
        {
            CMSEncryptedData encData = new CMSEncryptedData(org.bouncycastle.asn1.cms.ContentInfo.getInstance(info));

            try
            {
                this.safeBagSeq = ASN1Sequence.getInstance(encData.getContent(inputDecryptorProvider));
            }
            catch (CMSException e)
            {
                throw new PKCSException("unable to extract data: " + e.getMessage(), e);
            }
            return;
        }

        throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
    }

    /**
     * Return the {@link PKCS12SafeBag}s contained in the ContentInfo this factory was created over.
     *
     * @return the SafeBags as an array.
     */
    public PKCS12SafeBag[] getSafeBags()
    {
        PKCS12SafeBag[] safeBags = new PKCS12SafeBag[safeBagSeq.size()];

        for (int i = 0; i != safeBagSeq.size(); i++)
        {
            safeBags[i] = new PKCS12SafeBag(SafeBag.getInstance(safeBagSeq.getObjectAt(i)));
        }

        return safeBags;
    }
}
