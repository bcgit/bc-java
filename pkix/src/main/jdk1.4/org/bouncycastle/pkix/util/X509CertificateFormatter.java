package org.bouncycastle.pkix.util;

import java.io.FileReader;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

/**
 * A general class for X.509 certificate "pretty printing".
 */
public class X509CertificateFormatter
{
    private static Map<ASN1ObjectIdentifier, String> oidMap = new HashMap<ASN1ObjectIdentifier, String>();
    private static Map<ASN1ObjectIdentifier, String> keyAlgMap = new HashMap<ASN1ObjectIdentifier, String>();
    private static Map<KeyPurposeId, String> extUsageMap = new HashMap<KeyPurposeId, String>();

    private static Map<Integer, String> usageMap = new HashMap<Integer, String>();

    static
    {
        oidMap.put(Extension.subjectDirectoryAttributes, "subjectDirectoryAttributes");
        oidMap.put(Extension.subjectKeyIdentifier, "subjectKeyIdentifier");
        oidMap.put(Extension.keyUsage, "keyUsage");
        oidMap.put(Extension.privateKeyUsagePeriod, "privateKeyUsagePeriod");
        oidMap.put(Extension.subjectAlternativeName, "subjectAlternativeName");
        oidMap.put(Extension.issuerAlternativeName, "issuerAlternativeName");
        oidMap.put(Extension.basicConstraints, "basicConstraints");
        oidMap.put(Extension.cRLNumber, "cRLNumber");
        oidMap.put(Extension.reasonCode, "reasonCode");
        oidMap.put(Extension.instructionCode, "instructionCode");
        oidMap.put(Extension.invalidityDate, "invalidityDate");
        oidMap.put(Extension.deltaCRLIndicator, "deltaCRLIndicator");
        oidMap.put(Extension.issuingDistributionPoint, "issuingDistributionPoint");
        oidMap.put(Extension.certificateIssuer, "certificateIssuer");
        oidMap.put(Extension.nameConstraints, "nameConstraints");
        oidMap.put(Extension.cRLDistributionPoints, "cRLDistributionPoints");
        oidMap.put(Extension.certificatePolicies, "certificatePolicies");
        oidMap.put(Extension.policyMappings, "policyMappings");
        oidMap.put(Extension.authorityKeyIdentifier, "authorityKeyIdentifier");
        oidMap.put(Extension.policyConstraints, "policyConstraints");
        oidMap.put(Extension.extendedKeyUsage, "extendedKeyUsage");
        oidMap.put(Extension.freshestCRL, "freshestCRL");
        oidMap.put(Extension.inhibitAnyPolicy, "inhibitAnyPolicy");
        oidMap.put(Extension.authorityInfoAccess, "authorityInfoAccess");
        oidMap.put(Extension.subjectInfoAccess, "subjectInfoAccess");
        oidMap.put(Extension.logoType, "logoType");
        oidMap.put(Extension.biometricInfo, "biometricInfo");
        oidMap.put(Extension.qCStatements, "qCStatements");
        oidMap.put(Extension.auditIdentity, "auditIdentity");
        oidMap.put(Extension.noRevAvail, "noRevAvail");
        oidMap.put(Extension.targetInformation, "targetInformation");
        oidMap.put(Extension.expiredCertsOnCRL, "expiredCertsOnCRL");

        usageMap.put(Integers.valueOf(KeyUsage.digitalSignature), "digitalSignature");
        usageMap.put(Integers.valueOf(KeyUsage.nonRepudiation), "nonRepudiation");
        usageMap.put(Integers.valueOf(KeyUsage.keyEncipherment), "keyEncipherment");
        usageMap.put(Integers.valueOf(KeyUsage.dataEncipherment), "dataEncipherment");
        usageMap.put(Integers.valueOf(KeyUsage.keyAgreement), "keyAgreement");
        usageMap.put(Integers.valueOf(KeyUsage.keyCertSign), "keyCertSign");
        usageMap.put(Integers.valueOf(KeyUsage.cRLSign), "cRLSign");
        usageMap.put(Integers.valueOf(KeyUsage.encipherOnly), "encipherOnly");
        usageMap.put(Integers.valueOf(KeyUsage.decipherOnly), "decipherOnly");

        extUsageMap.put(KeyPurposeId.anyExtendedKeyUsage, "anyExtendedKeyUsage");
        extUsageMap.put(KeyPurposeId.id_kp_serverAuth, "id_kp_serverAuth");
        extUsageMap.put(KeyPurposeId.id_kp_clientAuth, "id_kp_clientAuth");
        extUsageMap.put(KeyPurposeId.id_kp_codeSigning, "id_kp_codeSigning");
        extUsageMap.put(KeyPurposeId.id_kp_emailProtection, "id_kp_emailProtection");
        extUsageMap.put(KeyPurposeId.id_kp_ipsecEndSystem, "id_kp_ipsecEndSystem");
        extUsageMap.put(KeyPurposeId.id_kp_ipsecTunnel, "id_kp_ipsecTunnel");
        extUsageMap.put(KeyPurposeId.id_kp_ipsecUser, "id_kp_ipsecUser");
        extUsageMap.put(KeyPurposeId.id_kp_timeStamping, "id_kp_timeStamping");
        extUsageMap.put(KeyPurposeId.id_kp_OCSPSigning, "id_kp_OCSPSigning");
        extUsageMap.put(KeyPurposeId.id_kp_dvcs, "id_kp_dvcs");
        extUsageMap.put(KeyPurposeId.id_kp_sbgpCertAAServerAuth, "id_kp_sbgpCertAAServerAuth");
        extUsageMap.put(KeyPurposeId.id_kp_scvp_responder, "id_kp_scvp_responder");
        extUsageMap.put(KeyPurposeId.id_kp_eapOverPPP, "id_kp_eapOverPPP");
        extUsageMap.put(KeyPurposeId.id_kp_eapOverLAN, "id_kp_eapOverLAN");
        extUsageMap.put(KeyPurposeId.id_kp_scvpServer, "id_kp_scvpServer");
        extUsageMap.put(KeyPurposeId.id_kp_scvpClient, "id_kp_scvpClient");
        extUsageMap.put(KeyPurposeId.id_kp_ipsecIKE, "id_kp_ipsecIKE");
        extUsageMap.put(KeyPurposeId.id_kp_capwapAC, "id_kp_capwapAC");
        extUsageMap.put(KeyPurposeId.id_kp_capwapWTP, "id_kp_capwapWTP");
        extUsageMap.put(KeyPurposeId.id_kp_cmcCA, "id_kp_cmcCA");
        extUsageMap.put(KeyPurposeId.id_kp_cmcRA, "id_kp_cmcRA");
        extUsageMap.put(KeyPurposeId.id_kp_cmKGA, "id_kp_cmKGA");
        extUsageMap.put(KeyPurposeId.id_kp_smartcardlogon, "id_kp_smartcardlogon");
        extUsageMap.put(KeyPurposeId.id_kp_macAddress, "id_kp_macAddress");
        extUsageMap.put(KeyPurposeId.id_kp_msSGC, "id_kp_msSGC");
        extUsageMap.put(KeyPurposeId.id_kp_nsSGC, "id_kp_nsSGC");

        keyAlgMap.put(PKCSObjectIdentifiers.rsaEncryption, "rsaEncryption");
        keyAlgMap.put(X9ObjectIdentifiers.id_ecPublicKey, "id_ecPublicKey");
        keyAlgMap.put(EdECObjectIdentifiers.id_Ed25519, "id_Ed25519");
        keyAlgMap.put(EdECObjectIdentifiers.id_Ed448, "id_Ed448");
    }

    private static String oidToLabel(ASN1ObjectIdentifier oid)
    {
        String oidStr = (String)oidMap.get(oid);
        if (oidStr != null)
        {
            return oidStr;
        }

        return oid.getId();
    }

    private static String keyAlgToLabel(ASN1ObjectIdentifier oid)
    {
        String oidStr = (String)keyAlgMap.get(oid);
        if (oidStr != null)
        {
            return oidStr;
        }

        return oid.getId();
    }

    private static final String spaceStr = "                                                              ";

    private static String spaces(int length)
    {
        return spaceStr.substring(0, length);
    }

    private static String indent(String pad, String detail, String nl)
    {
        StringBuffer bld = new StringBuffer();
        int index;
        int last = 0;
        detail = detail.substring(0, detail.length() - nl.length());
        while ((index = detail.indexOf(nl)) > 0)
        {
            bld.append(detail.substring(last, index));
            bld.append(nl);
            bld.append(pad);
            if (last < detail.length())
            {
                detail = detail.substring(index + nl.length());
            }
        }
        // a single line.
        if (bld.length() == 0)
        {
            return detail;
        }
        else
        {
            bld.append(detail);
        }
        return bld.toString();
    }

    static void prettyPrintData(byte[] sig, StringBuffer buf, String nl)
    {
        if (sig.length > 20)
        {
        // -DM Hex.toHexString
            buf.append(Hex.toHexString(sig, 0, 20)).append(nl);
            format(buf, sig, nl);
        }
        else
        {
        // -DM Hex.toHexString
            buf.append(Hex.toHexString(sig)).append(nl);
        }
    }

    static void format(StringBuffer buf, byte[] data, String nl)
    {
        for (int i = 20; i < data.length; i += 20)
        {
            if (i < data.length - 20)
            {
        // -DM Hex.toHexString
                buf.append("                       ").append(Hex.toHexString(data, i, 20)).append(nl);
            }
            else
            {
        // -DM Hex.toHexString
                buf.append("                       ").append(Hex.toHexString(data, i, data.length - i)).append(nl);
            }
        }
    }

    public static String asString(X509CertificateHolder certHolder)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        String sigAlgorithm = new DefaultSignatureNameFinder().getAlgorithmName(certHolder.getSignatureAlgorithm());

        //sigAlgorithm = sigAlgorithm.replace("WITH", "with");

        String pubKeyAlgorithm = keyAlgToLabel(certHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm());

        buf.append("  [0]         Version: ").append(certHolder.getVersionNumber()).append(nl);
        buf.append("         SerialNumber: ").append(certHolder.getSerialNumber()).append(nl);
        buf.append("             IssuerDN: ").append(certHolder.getIssuer()).append(nl);
        buf.append("           Start Date: ").append(certHolder.getNotBefore()).append(nl);
        buf.append("           Final Date: ").append(certHolder.getNotAfter()).append(nl);
        buf.append("            SubjectDN: ").append(certHolder.getSubject()).append(nl);
        buf.append("           Public Key: ").append(pubKeyAlgorithm).append(nl);
        buf.append("                       ");
        prettyPrintData(certHolder.getSubjectPublicKeyInfo().getPublicKeyData().getOctets(), buf, nl);

        Extensions extensions = certHolder.getExtensions();

        if (extensions != null)
        {
            Enumeration e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("           Extensions: ").append(nl);
            }

            while (e.hasMoreElements())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                Extension ext = extensions.getExtension(oid);

                if (ext.getExtnValue() != null)
                {
                    byte[] octs = ext.getExtnValue().getOctets();
                    ASN1InputStream dIn = new ASN1InputStream(octs);
                    String pad = "                       ";
                    try
                    {
                        String label = oidToLabel(oid);
                        buf.append(pad).append(label);
                        buf.append(": critical(").append(ext.isCritical()).append(") ").append(nl);
                        pad += spaces(2 + label.length());
                        if (oid.equals(Extension.basicConstraints))
                        {
                            BasicConstraints bc = BasicConstraints.getInstance(dIn.readObject());

                            buf.append(pad).append("isCA : " + bc.isCA()).append(nl);
                            if (bc.isCA())
                            {
                                buf.append(spaces(2 + label.length()));
                                buf.append("pathLenConstraint : " + bc.getPathLenConstraint()).append(nl);
                            }
                        }
                        else if (oid.equals(Extension.keyUsage))
                        {
                            KeyUsage usage = KeyUsage.getInstance(dIn.readObject());

                            buf.append(pad);
                            boolean first = true;
                            for (Iterator<Integer> it = usageMap.keySet().iterator(); it.hasNext(); )
                            {
                                int bit = ((Integer)it.next()).intValue();
                                if (usage.hasUsages(bit))
                                {
                                    if (!first)
                                    {
                                        buf.append(", ");
                                    }
                                    else
                                    {
                                        first = false;
                                    }
                                    buf.append(usageMap.get(Integers.valueOf(bit)));
                                }
                            }
                            buf.append(nl);
                        }
                        else if (oid.equals(Extension.extendedKeyUsage))
                        {
                            ExtendedKeyUsage usage = ExtendedKeyUsage.getInstance(dIn.readObject());

                            buf.append(pad);
                            boolean first = true;
                            for (Iterator<KeyPurposeId> it = extUsageMap.keySet().iterator(); it.hasNext(); )
                            {
                                KeyPurposeId purpose = (KeyPurposeId)it.next();
                                if (usage.hasKeyPurposeId(purpose))
                                {
                                    if (!first)
                                    {
                                        buf.append(", ");
                                    }
                                    else
                                    {
                                        first = false;
                                    }
                                    buf.append(extUsageMap.get(purpose));
                                }
                            }
                            buf.append(nl);
                        }
                        else
                        {
                            buf.append(pad).append("value = ").append(indent(pad + spaces(8), ASN1Dump.dumpAsString(dIn.readObject()), nl)).append(nl);
                            //buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    catch (Exception ex)
                    {
                        ex.printStackTrace();
                        buf.append(oid.getId());
                        //     buf.append(" value = ").append(new String(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        buf.append("  Signature Algorithm: ").append(sigAlgorithm).append(nl);
        buf.append("            Signature: ");

        prettyPrintData(certHolder.getSignature(), buf, nl);
        
        return buf.toString();
    }

    public static void main(String[] args)
        throws Exception
    {
        PEMParser p = new PEMParser(new FileReader(args[0]));

        // -DM System.out.println
        System.out.println(asString((X509CertificateHolder)p.readObject()));
    }
}
