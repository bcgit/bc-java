package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertDiscoveryMethod;
import org.bouncycastle.asn1.x509.CertificatePair;
import org.bouncycastle.asn1.x509.DeltaCertificateDescriptor;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.ObjectDigestInfo;
import org.bouncycastle.asn1.x509.PolicyConstraints;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.RelatedCertificateDescriptor;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The OPTIONAL tagged fields of the X.509 SEQUENCE types may each appear at most once and only
 * in definition order: duplicates, reordered fields, non-context tags and trailing elements are
 * rejected, while every legal combination still parses (github #2516).
 */
public class X509SequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final AlgorithmIdentifier SHA256_RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final X500Name NAME = new X500Name("CN=Test");
    private static final GeneralNames GN = new GeneralNames(new GeneralName(GeneralName.dNSName, "a.example"));
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final SubjectPublicKeyInfo SPKI = new SubjectPublicKeyInfo(RSA, new byte[]{ 0 });

    public String getName()
    {
        return "X509SequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, tagNo, base);
    }

    private static ASN1Encodable app(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, BERTags.APPLICATION, tagNo, base);
    }

    private static ASN1Encodable[] els(ASN1Encodable a)
    {
        return new ASN1Encodable[]{ a };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b)
    {
        return new ASN1Encodable[]{ a, b };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c)
    {
        return new ASN1Encodable[]{ a, b, c };
    }

    private static ASN1Encodable[] concat(ASN1Encodable[] head, ASN1Encodable[] tail)
    {
        ASN1Encodable[] all = new ASN1Encodable[head.length + tail.length];
        System.arraycopy(head, 0, all, 0, head.length);
        System.arraycopy(tail, 0, all, head.length, tail.length);
        return all;
    }

    // round trip through the encoding so the parser sees tagged objects as they come off the wire
    private static ASN1Sequence wire(ASN1Encodable[] elements)
        throws IOException
    {
        return ASN1Sequence.getInstance(new DERSequence(elements).getEncoded());
    }

    private void accepts(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
        }
        catch (IllegalArgumentException e)
        {
            fail(label + " rejected a valid encoding: " + e.getMessage());
        }
    }

    private void rejects(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
            fail(label + " accepted an invalid encoding");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void performTest()
        throws Exception
    {
        authorityKeyIdentifier();
        distributionPoints();
        nameAndPolicyConstraints();
        privateKeyUsagePeriod();
        attributeCertificateTypes();
        certificatePair();
        tbsCertificate();
        tbsCertificateStructure();
        tbsCertificateLogEntry();
        tbsCertList();
        deltaCertificateDescriptor();
        relatedCertificateDescriptor();
    }

    private void authorityKeyIdentifier()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return AuthorityKeyIdentifier.getInstance(seq);
            }
        };
        ASN1Encodable keyId = ctx(0, false, new DEROctetString(new byte[]{ 1 }));
        accepts("AKI", p, els(keyId));
        accepts("AKI", p, els(keyId, ctx(1, false, GN), ctx(2, false, ONE)));
        rejects("AKI duplicate", p, els(keyId, ctx(0, false, new DEROctetString(new byte[]{ 2 }))));
        rejects("AKI order", p, els(ctx(1, false, GN), ctx(2, false, ONE), keyId));
        rejects("AKI class", p, els(app(0, false, new DEROctetString(new byte[]{ 1 }))));
        rejects("AKI untagged", p, els(keyId, ONE));
    }

    private void distributionPoints()
        throws IOException
    {
        Parser dp = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DistributionPoint.getInstance(seq);
            }
        };
        ASN1Encodable name = ctx(0, true, new DistributionPointName(GN));
        ASN1Encodable reasons = ctx(1, false, new DERBitString(new byte[]{ (byte)0x80 }, 7));
        accepts("DistributionPoint", dp, els(name, reasons, ctx(2, false, GN)));
        rejects("DistributionPoint duplicate", dp, els(name, ctx(2, false, GN), ctx(2, false, GN)));
        rejects("DistributionPoint order", dp, els(ctx(2, false, GN), name));

        Parser idp = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return IssuingDistributionPoint.getInstance(seq);
            }
        };
        accepts("IDP", idp, els(name, ctx(1, false, ASN1Boolean.TRUE), ctx(4, false, ASN1Boolean.TRUE)));
        rejects("IDP duplicate", idp, els(ctx(1, false, ASN1Boolean.TRUE), ctx(1, false, ASN1Boolean.FALSE)));
        rejects("IDP order", idp, els(ctx(4, false, ASN1Boolean.TRUE), ctx(1, false, ASN1Boolean.TRUE)));
        rejects("IDP class", idp, els(app(1, false, ASN1Boolean.TRUE)));
    }

    private void nameAndPolicyConstraints()
        throws IOException
    {
        Parser nc = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return NameConstraints.getInstance(seq);
            }
        };
        ASN1Encodable subtrees = new DERSequence(new GeneralSubtree(new GeneralName(GeneralName.dNSName, "a.example")));
        accepts("NameConstraints", nc, els(ctx(0, false, subtrees), ctx(1, false, subtrees)));
        accepts("NameConstraints", nc, els(ctx(1, false, subtrees)));
        rejects("NameConstraints duplicate", nc, els(ctx(0, false, subtrees), ctx(0, false, subtrees)));
        rejects("NameConstraints order", nc, els(ctx(1, false, subtrees), ctx(0, false, subtrees)));

        Parser pc = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PolicyConstraints.getInstance(seq);
            }
        };
        accepts("PolicyConstraints", pc, els(ctx(0, false, ONE), ctx(1, false, ONE)));
        rejects("PolicyConstraints duplicate", pc, els(ctx(1, false, ONE), ctx(1, false, ONE)));
        rejects("PolicyConstraints order", pc, els(ctx(1, false, ONE), ctx(0, false, ONE)));
    }

    private void privateKeyUsagePeriod()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PrivateKeyUsagePeriod.getInstance(seq);
            }
        };
        ASN1Encodable t0 = ctx(0, false, new ASN1GeneralizedTime(new Date(0)));
        ASN1Encodable t1 = ctx(1, false, new ASN1GeneralizedTime(new Date(1000000000000L)));
        accepts("PrivateKeyUsagePeriod", p, els(t0, t1));
        rejects("PrivateKeyUsagePeriod duplicate", p, els(t0, t0));
        rejects("PrivateKeyUsagePeriod order", p, els(t1, t0));
        rejects("PrivateKeyUsagePeriod unknown tag", p, els(t0, ctx(2, false, new ASN1GeneralizedTime(new Date(0)))));
        rejects("PrivateKeyUsagePeriod untagged", p, els(t0, ONE));
    }

    private void attributeCertificateTypes()
        throws IOException
    {
        ASN1Encodable issuerSerial = ctx(0, false, new IssuerSerial(GN, ONE));
        ASN1Encodable odi = ctx(1, false, new ObjectDigestInfo(ObjectDigestInfo.publicKey, null, SHA256_RSA, new byte[32]));

        Parser holder = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return Holder.getInstance(seq);
            }
        };
        accepts("Holder", holder, els(issuerSerial, ctx(1, false, GN)));
        rejects("Holder duplicate", holder, els(ctx(1, false, GN), ctx(1, false, GN)));
        rejects("Holder order", holder, els(ctx(1, false, GN), issuerSerial));

        Parser v2Form = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return V2Form.getInstance(seq);
            }
        };
        accepts("V2Form", v2Form, els(GN, issuerSerial, odi));
        rejects("V2Form duplicate", v2Form, els(GN, issuerSerial, issuerSerial));
        rejects("V2Form order", v2Form, els(odi, issuerSerial));

        Parser role = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RoleSyntax.getInstance(seq);
            }
        };
        ASN1Encodable roleName = ctx(1, true, new GeneralName(GeneralName.uniformResourceIdentifier, "urn:role"));
        accepts("RoleSyntax", role, els(ctx(0, false, GN), roleName));
        rejects("RoleSyntax duplicate", role, els(roleName, roleName));
        rejects("RoleSyntax order", role, els(roleName, ctx(0, false, GN)));
    }

    private Certificate certificate()
    {
        V3TBSCertificateGenerator gen = new V3TBSCertificateGenerator();
        gen.setSerialNumber(ONE);
        gen.setSignature(SHA256_RSA);
        gen.setIssuer(NAME);
        gen.setStartDate(new Time(new Date(0)));
        gen.setEndDate(new Time(new Date(1000000000000L)));
        gen.setSubject(NAME);
        gen.setSubjectPublicKeyInfo(SPKI);
        return Certificate.getInstance(new DERSequence(els(gen.generateTBSCertificate(), SHA256_RSA, new DERBitString(new byte[]{ 0 }))));
    }

    private void certificatePair()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertificatePair.getInstance(seq);
            }
        };
        Certificate cert = certificate();
        accepts("CertificatePair", p, els(ctx(0, true, cert), ctx(1, true, cert)));
        rejects("CertificatePair duplicate", p, els(ctx(0, true, cert), ctx(0, true, cert)));
        rejects("CertificatePair order", p, els(ctx(1, true, cert), ctx(0, true, cert)));
    }

    private static ASN1Encodable extensionsBlock(boolean ca)
        throws IOException
    {
        return new Extensions(new Extension(Extension.basicConstraints, true, new BasicConstraints(ca).getEncoded()));
    }

    // version [0] v3, serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    private static ASN1Encodable[] tbsHead()
    {
        return new ASN1Encodable[]{ ctx(0, true, new ASN1Integer(2)), ONE, SHA256_RSA, NAME,
            new Validity(new Time(new Date(0)), new Time(new Date(1000000000000L))), NAME, SPKI };
    }

    private void tbsCertificate()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TBSCertificate.getInstance(seq);
            }
        };
        ASN1Encodable uid1 = ctx(1, false, new DERBitString(new byte[]{ 1 }));
        ASN1Encodable uid2 = ctx(2, false, new DERBitString(new byte[]{ 2 }));
        ASN1Encodable extsFalse = ctx(3, true, extensionsBlock(false));
        ASN1Encodable extsTrue = ctx(3, true, extensionsBlock(true));

        accepts("TBSCertificate", p, tbsHead());
        accepts("TBSCertificate", p, concat(tbsHead(), els(extsFalse)));
        accepts("TBSCertificate", p, concat(tbsHead(), els(uid1, uid2, extsFalse)));
        rejects("TBSCertificate two extension blocks", p, concat(tbsHead(), els(extsFalse, extsTrue)));
        rejects("TBSCertificate duplicate uid", p, concat(tbsHead(), els(uid1, uid1)));
        rejects("TBSCertificate order", p, concat(tbsHead(), els(extsFalse, uid1)));
        rejects("TBSCertificate untagged", p, concat(tbsHead(), els(extsFalse, ONE)));
        rejects("TBSCertificate class", p, concat(tbsHead(), els(app(3, true, extensionsBlock(false)))));

        // the reviewer reports each problem rather than stopping at the first
        List problems = TBSCertificate.reviewStructure(wire(concat(tbsHead(), els(extsFalse, extsTrue, ONE))));
        isEquals("reviewer problem count", 2, problems.size());
        isTrue("reviewer repeated tag", ((Exception)problems.get(0)).getMessage().startsWith("tag [3] repeated or out of order"));
        isTrue("reviewer untagged", ((Exception)problems.get(1)).getMessage().startsWith("unexpected element at position"));
        isEquals("reviewer clean", 0, TBSCertificate.reviewStructure(wire(concat(tbsHead(), els(uid1, uid2, extsFalse)))).size());
    }

    private void tbsCertificateStructure()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TBSCertificateStructure.getInstance(seq);
            }
        };
        ASN1Encodable uid1 = ctx(1, false, new DERBitString(new byte[]{ 1 }));
        ASN1Encodable exts = ctx(3, true, extensionsBlock(false));
        accepts("TBSCertificateStructure", p, concat(tbsHead(), els(uid1, exts)));
        rejects("TBSCertificateStructure duplicate", p, concat(tbsHead(), els(exts, exts)));
        rejects("TBSCertificateStructure order", p, concat(tbsHead(), els(exts, uid1)));
        rejects("TBSCertificateStructure unknown tag", p, concat(tbsHead(), els(ctx(5, false, ONE))));
    }

    private void tbsCertificateLogEntry()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TBSCertificateLogEntry.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ctx(0, true, new ASN1Integer(2)), NAME,
            new Validity(new Time(new Date(0)), new Time(new Date(1000000000000L))), NAME, RSA, new DEROctetString(new byte[32]) };
        ASN1Encodable uid1 = ctx(1, false, new DERBitString(new byte[]{ 1 }));
        ASN1Encodable exts = ctx(3, true, extensionsBlock(false));
        accepts("TBSCertificateLogEntry", p, concat(head, els(uid1, exts)));
        rejects("TBSCertificateLogEntry duplicate", p, concat(head, els(exts, exts)));
        rejects("TBSCertificateLogEntry order", p, concat(head, els(exts, uid1)));
    }

    private void tbsCertList()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TBSCertList.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ONE, SHA256_RSA, NAME, new DERUTCTime(new Date(0)) };
        ASN1Encodable exts = ctx(0, true, extensionsBlock(false));
        accepts("TBSCertList", p, head);
        accepts("TBSCertList", p, concat(head, els(exts)));
        rejects("TBSCertList two extension blocks", p, concat(head, els(exts, exts)));
        rejects("TBSCertList trailing element", p, concat(head, els(exts, ONE)));
        rejects("TBSCertList wrong tag", p, concat(head, els(ctx(1, true, extensionsBlock(false)))));
        rejects("TBSCertList class", p, concat(head, els(app(0, true, extensionsBlock(false)))));
    }

    private void deltaCertificateDescriptor()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DeltaCertificateDescriptor.getInstance(seq);
            }
        };
        ASN1Encodable sig = ctx(0, true, SHA256_RSA);
        ASN1Encodable issuer = ctx(1, true, NAME);
        ASN1Encodable subject = ctx(3, true, NAME);
        ASN1Encodable exts = ctx(4, true, extensionsBlock(false));
        ASN1Encodable sigValue = new DERBitString(new byte[]{ 0 });

        accepts("DeltaCertificateDescriptor", p, els(ONE, SPKI, sigValue));
        accepts("DeltaCertificateDescriptor", p, concat(els(ONE, sig, issuer), concat(els(subject, SPKI, exts), els(sigValue))));
        rejects("DeltaCertificateDescriptor duplicate", p, concat(els(ONE, issuer, issuer), els(SPKI, sigValue)));
        rejects("DeltaCertificateDescriptor order", p, concat(els(ONE, subject, issuer), els(SPKI, sigValue)));
        rejects("DeltaCertificateDescriptor unknown tag", p, concat(els(ONE, ctx(5, true, NAME)), els(SPKI, sigValue)));
        rejects("DeltaCertificateDescriptor two extension blocks", p, concat(els(ONE, SPKI, exts), els(exts, sigValue)));
        rejects("DeltaCertificateDescriptor trailing element", p, els(ONE, SPKI, sigValue, ONE));
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c, ASN1Encodable d)
    {
        return new ASN1Encodable[]{ a, b, c, d };
    }

    private void relatedCertificateDescriptor()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RelatedCertificateDescriptor.getInstance(seq);
            }
        };
        ASN1Encodable method = CertDiscoveryMethod.byUri("https://a.example/cert");
        ASN1Encodable intent = new ASN1ObjectIdentifier("1.2.3.4");
        ASN1Encodable sigAlg = ctx(0, false, SHA256_RSA);
        ASN1Encodable keyAlg = ctx(1, false, RSA);

        accepts("RelatedCertificateDescriptor", p, els(method));
        accepts("RelatedCertificateDescriptor", p, els(method, intent, sigAlg, keyAlg));
        accepts("RelatedCertificateDescriptor", p, els(method, keyAlg));
        rejects("RelatedCertificateDescriptor duplicate", p, els(method, sigAlg, sigAlg));
        rejects("RelatedCertificateDescriptor order", p, els(method, keyAlg, sigAlg));
        rejects("RelatedCertificateDescriptor intent after tags", p, els(method, sigAlg, intent));
        rejects("RelatedCertificateDescriptor unknown tag", p, els(method, ctx(2, false, RSA)));
    }

    public static void main(String[] args)
    {
        runTest(new X509SequenceFieldOrderTest());
    }
}
