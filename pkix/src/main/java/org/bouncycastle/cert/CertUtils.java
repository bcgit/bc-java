package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Properties;

class CertUtils
{
    private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
    private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

    static ASN1Primitive parseNonEmptyASN1(byte[] encoding)
        throws IOException
    {
        ASN1Primitive p = ASN1Primitive.fromByteArray(encoding);

        if (p == null)
        {
            throw new IOException("no content found");
        }
        return p;
    }


    static X509CertificateHolder generateFullCert(ContentSigner signer, TBSCertificate tbsCert)
    {
        try
        {
            return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCert)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certificate signature");
        }
    }

    static X509AttributeCertificateHolder generateFullAttrCert(ContentSigner signer, AttributeCertificateInfo attrInfo)
    {
        try
        {
            return new X509AttributeCertificateHolder(generateAttrStructure(attrInfo, signer.getAlgorithmIdentifier(), generateSig(signer, attrInfo)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce attribute certificate signature");
        }
    }

    static X509CRLHolder generateFullCRL(ContentSigner signer, TBSCertList tbsCertList)
    {
        try
        {
            return new X509CRLHolder(generateCRLStructure(tbsCertList, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCertList)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certificate signature");
        }
    }

    private static byte[] generateSig(ContentSigner signer, ASN1Object tbsObj)
        throws IOException
    {
        OutputStream sOut = signer.getOutputStream();
        tbsObj.encodeTo(sOut, ASN1Encoding.DER);
        sOut.close();

        return signer.getSignature();
    }

    private static Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));

        return Certificate.getInstance(new DERSequence(v));
    }

    private static AttributeCertificate generateAttrStructure(AttributeCertificateInfo attrInfo, AlgorithmIdentifier sigAlgId, byte[] signature)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attrInfo);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));

        return AttributeCertificate.getInstance(new DERSequence(v));
    }

    private static CertificateList generateCRLStructure(TBSCertList tbsCertList, AlgorithmIdentifier sigAlgId, byte[] signature)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCertList);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));

        return CertificateList.getInstance(new DERSequence(v));
    }

    static Set getCriticalExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
    }

    static Set getNonCriticalExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        // TODO: should probably produce a set that imposes correct ordering
        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
    }

    static List getExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_LIST;
        }

        return Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
    }

    static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }
    }

    static DERBitString booleanToBitString(boolean[] id)
    {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++)
        {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0)
        {
            return new DERBitString(bytes);
        }
        else
        {
            return new DERBitString(bytes, 8 - pad);
        }
    }

    static boolean[] bitStringToBoolean(DERBitString bitString)
    {
        if (bitString != null)
        {
            byte[]          bytes = bitString.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - bitString.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }

        return null;
    }

    static Date recoverDate(ASN1GeneralizedTime time)
    {
        try
        {
            return time.getDate();
        }
        catch (ParseException e)
        {
            throw new IllegalStateException("unable to recover date: " + e.getMessage());
        }
    }

    static boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
    {
        if (!id1.getAlgorithm().equals(id2.getAlgorithm()))
         {
             return false;
         }

         if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL"))
         {
             if (id1.getParameters() == null)
             {
                 if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE))
                 {
                     return false;
                 }

                 return true;
             }

             if (id2.getParameters() == null)
             {
                 if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE))
                 {
                     return false;
                 }

                 return true;
             }
         }

         if (id1.getParameters() != null)
         {
             return id1.getParameters().equals(id2.getParameters());
         }

         if (id2.getParameters() != null)
         {
             return id2.getParameters().equals(id1.getParameters());
         }

         return true;
    }

    static ExtensionsGenerator doReplaceExtension(ExtensionsGenerator extGenerator, Extension ext)
    {
        boolean isReplaced = false;
        Extensions exts = extGenerator.generate();
        extGenerator = new ExtensionsGenerator();

        for (Enumeration en = exts.oids(); en.hasMoreElements();)
        {
            ASN1ObjectIdentifier extOid = (ASN1ObjectIdentifier)en.nextElement();

            if (extOid.equals(ext.getExtnId()))
            {
                isReplaced = true;
                extGenerator.addExtension(ext);
            }
            else
            {
                extGenerator.addExtension(exts.getExtension(extOid));
            }
        }

        if (!isReplaced)
        {
            throw new IllegalArgumentException("replace - original extension (OID = " + ext.getExtnId() + ") not found");
        }

        return extGenerator;
    }

    static ExtensionsGenerator doRemoveExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier  oid)
    {
        boolean isRemoved = false;
        Extensions exts = extGenerator.generate();
        extGenerator = new ExtensionsGenerator();

        for (Enumeration en = exts.oids(); en.hasMoreElements();)
        {
            ASN1ObjectIdentifier extOid = (ASN1ObjectIdentifier)en.nextElement();

            if (extOid.equals(oid))
            {
                isRemoved = true;
            }
            else
            {
                extGenerator.addExtension(exts.getExtension(extOid));
            }
        }

        if (!isRemoved)
        {
            throw new IllegalArgumentException("remove - extension (OID = " + oid + ") not found");
        }

        return extGenerator;
    }
}
