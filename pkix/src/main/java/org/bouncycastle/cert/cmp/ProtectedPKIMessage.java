package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.util.Arrays;

/**
 * Wrapper for a PKIMessage with protection attached to it.
 */
public class ProtectedPKIMessage
{
    private PKIMessage pkiMessage;

    /**
     * Base constructor.
     *
     * @param pkiMessage a GeneralPKIMessage with
     */
    public ProtectedPKIMessage(GeneralPKIMessage pkiMessage)
    {
        if (!pkiMessage.hasProtection())
        {
            throw new IllegalArgumentException("PKIMessage not protected");
        }
        
        this.pkiMessage = pkiMessage.toASN1Structure();
    }

    ProtectedPKIMessage(PKIMessage pkiMessage)
    {
        if (pkiMessage.getHeader().getProtectionAlg() == null)
        {
            throw new IllegalArgumentException("PKIMessage not protected");
        }

        this.pkiMessage = pkiMessage;
    }

    /**
     * Return the message header.
     *
     * @return the message's PKIHeader structure.
     */
    public PKIHeader getHeader()
    {
        return pkiMessage.getHeader();
    }

    /**
     * Return the message body.
     *
     * @return the message's PKIBody structure.
     */
    public PKIBody getBody()
    {
        return pkiMessage.getBody();
    }

    /**
     * Return the underlying ASN.1 structure contained in this object.
     *
     * @return a PKIMessage structure.
     */
    public PKIMessage toASN1Structure()
    {
        return pkiMessage;
    }

    /**
     * Determine whether the message is protected by a CMP password based MAC. Use verify(PBEMacCalculatorProvider, char[])
     * to verify the message if this method returns true.
     *
     * @return true if protection MAC PBE based, false otherwise.
     */
    public boolean hasPasswordBasedMacProtection()
    {
        return CMPObjectIdentifiers.passwordBasedMac.equals(getProtectionAlgorithm().getAlgorithm());
    }

    /**
     * Return the message's protection algorithm.
     *
     * @return the algorithm ID for the message's protection algorithm.
     */
    public AlgorithmIdentifier getProtectionAlgorithm()
    {
        return pkiMessage.getHeader().getProtectionAlg();
    }

    /**
     * Return the extra certificates associated with this message.
     *
     * @return an array of extra certificates, zero length if none present.
     */
    public X509CertificateHolder[] getCertificates()
    {
        CMPCertificate[] certs = pkiMessage.getExtraCerts();

        if (certs == null)
        {
            return new X509CertificateHolder[0];
        }

        X509CertificateHolder[] res = new X509CertificateHolder[certs.length];
        for (int i = 0; i != certs.length; i++)
        {
            res[i] = new X509CertificateHolder(certs[i].getX509v3PKCert());
        }

        return res;
    }

    /**
     * Verify a message with a public key based signature attached.
     *
     * @param verifierProvider a provider of signature verifiers.
     * @return true if the provider is able to create a verifier that validates
     * the signature, false otherwise.
     * @throws CMPException if an exception is thrown trying to verify the signature.
     */
    public boolean verify(ContentVerifierProvider verifierProvider)
        throws CMPException
    {
        try
        {
            ContentVerifier verifier = verifierProvider.get(getProtectionAlgorithm());

            return verifySignature(pkiMessage.getProtection().getOctets(), verifier);
        }
        catch (Exception e)
        {
            throw new CMPException("unable to verify signature: " + e.getMessage(), e);
        }
    }

    /**
     * Verify a message with password based MAC protection.
     *
     * @param pbeMacCalculatorProvider MAC builder that can be used to construct the appropriate MacCalculator
     * @param password the MAC password
     * @return true if the passed in password and MAC builder verify the message, false otherwise.
     * @throws CMPException if algorithm not MAC based, or an exception is thrown verifying the MAC.
     */
    public boolean verify(PBEMacCalculatorProvider pbeMacCalculatorProvider, char[] password)
        throws CMPException
    {
        try
        {
            MacCalculator calculator = pbeMacCalculatorProvider.get(getProtectionAlgorithm(), password);

            CMPUtil.derEncodeToStream(createProtected(), calculator.getOutputStream());

            return Arrays.constantTimeAreEqual(calculator.getMac(), pkiMessage.getProtection().getOctets());
        }
        catch (Exception e)
        {
            throw new CMPException("unable to verify MAC: " + e.getMessage(), e);
        }
    }

    private boolean verifySignature(byte[] signature, ContentVerifier verifier)
    {
        CMPUtil.derEncodeToStream(createProtected(), verifier.getOutputStream());

        return verifier.verify(signature);
    }

    private DERSequence createProtected()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(pkiMessage.getHeader());
        v.add(pkiMessage.getBody());
        return new DERSequence(v);
    }
}
