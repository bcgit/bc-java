package org.bouncycastle.cert.ct.test;

import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ct.SctExtension;
import org.bouncycastle.cert.ct.SignedCertificateTimestamp;
import org.bouncycastle.cert.ct.SignedCertificateTimestampDataV2;
import org.bouncycastle.cert.ct.SignedCertificateTimestampList;
import org.bouncycastle.cert.ct.TransItem;
import org.bouncycastle.cert.ct.TransItemList;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Round-trip tests for the Certificate Transparency decoders covering both
 * RFC 6962 (v1) and RFC 9162 (v2). The wire-format vectors are
 * hand-constructed because no current CT log issues v2 in the wild — the
 * point of the test is to exercise the encode / decode paths.
 */
public class CertificateTransparencyTest
    extends SimpleTest
{
    private static final byte[] LOG_ID_32 = new byte[32];
    static
    {
        for (int i = 0; i < LOG_ID_32.length; i++)
        {
            LOG_ID_32[i] = (byte)(0x40 + i);
        }
    }

    private static final long TIMESTAMP = 0x0000017F11FBD420L;

    private static final byte[] SIGNATURE_71 = new byte[71];
    static
    {
        for (int i = 0; i < SIGNATURE_71.length; i++)
        {
            SIGNATURE_71[i] = (byte)i;
        }
    }

    // the www.bouncycastle.org server certificate (Let's Encrypt), carrying two embedded RFC 6962 SCTs
    private static final byte[] BC_SERVER_CERT = Base64.decode(
        "MIIFUTCCBDmgAwIBAgISBhvVwJPlXY4QbADq6XPooit+MA0GCSqGSIb3DQEBCwUA"
            + "MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD"
            + "EwNZUjIwHhcNMjYxMDE0MDUyMzAwWhcNMjcwMTEyMDUyMjU5WjAkMSIwIAYDVQQD"
            + "ExltYWlsLm5ldy5ib3VuY3ljYXN0bGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOC"
            + "AQ8AMIIBCgKCAQEAtiKv//IGSq16DnMKJHM4cf6zEXZ9iKVHz41ba3Y3MeUcB2nw"
            + "EpoFxyxTdAfr8LmCjLkawpb+LEF/T76Dx2EVZYE6s7Qw9I1x/ozhVO1AaTA910bG"
            + "fqDX2sXqt81p7nHHVPeXZtm22DsrO3LWAzV8pOyXRprdjg1oCZeg3mdzEMyqVZME"
            + "Q3chyk8LMITybshF9Vv8AKAyv+7llehFiVFWkxKuBHFJ81mphO2rM1oK1t57cbQB"
            + "nwt5CsLf6aXOSOoVCVtYuPVh0v8q0J+g1qHP2IlmyO4Oqm72YhH89FdmB9lOOs+y"
            + "W27tvrfbHSSytJZezLZGwxYsiBL8yoOEHUd9gwIDAQABo4ICbDCCAmgwDgYDVR0P"
            + "AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYD"
            + "VR0OBBYEFNQeU8nQLdl+uv/WLGIKYFgXDh8VMB8GA1UdIwQYMBaAFEAVLSZ57TIg"
            + "nt+ach3WMh+BDIEMMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAoYXaHR0cDov"
            + "L3lyMi5pLmxlbmNyLm9yZy8wZgYDVR0RBF8wXYISKi5ib3VuY3ljYXN0bGUub3Jn"
            + "gg0qLm9wZW5qY2Uub3JnghBib3VuY3ljYXN0bGUub3JnghltYWlsLm5ldy5ib3Vu"
            + "Y3ljYXN0bGUub3JnggtvcGVuamNlLm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATAv"
            + "BgNVHR8EKDAmMCSgIqAghh5odHRwOi8veXIyLmMubGVuY3Iub3JnLzEyNy5jcmww"
            + "ggEOBgorBgEEAdZ5AgQCBIH/BIH8APoAdwBMY9yY5Zwdq4j2Hoo93q6Pq0SjN3tf"
            + "m5TD+6Gc/MG+JgAAAaE5ErnBAAAEAwBIMEYCIQCl6Wn+j43rmfBm3ascFTJwJXN4"
            + "W70omulx/89iLOl1jQIhAJp/rZuId9RTPRnWJpFfYX81yc2ceTqIjLoWQzELiZz2"
            + "AH8AooEAGHNOF24dR+CVQPOBulRml81jqENQcW64CU7a8Q0AAAGhORK8hgAIAAAF"
            + "ACNVi18EAwBIMEYCIQDA50DbgqS+q6+B/b4y9SKt84yI6TTqRdrYSevhHkCiDwIh"
            + "AOWaiLyAxJZhNCVoh7uQ81nc7CKb18b7ZwMB3nCMhIQWMA0GCSqGSIb3DQEBCwUA"
            + "A4IBAQBL8tMqdPhNXpwV/1EGpJvj20acEU/Uq0EE3w0mTZZEX0qBancJxdpYxiqq"
            + "GCsDdWnvatXg1M/IG9RpmtjxXieDdA6anGGivY0ZDi+DTQa4MXOXEFDCFxUAZclN"
            + "o3IFrdQNDsefrAI+abbSC5kBBclqHs1BDZx3xgRcZ8T5kudhvv7BN4xjnrNgH2tf"
            + "b21+4tMQ2iCWdz0/hVZMs2miEJ90w+CrKey2GTPFg49Y88RxB7ICmdaI1Swc5jzQ"
            + "zv9rLqIU4C/Uy+fEGoJ6wOCJ1vwU/Ifo9wSme5QQqXu5g47ve8pbOGKb0w1zFWrL"
            + "URIRQR+ITi4NCCiX2bsupbLgpOBz");

    public String getName()
    {
        return "CertificateTransparency";
    }

    public void performTest()
        throws Exception
    {
        testV1SctRoundTrip();
        testV1ListRoundTripAndFromExtensions();
        testV2SctDataRoundTrip();
        testV2TransItemListRoundTripAndFromExtensions();
        testV1ListAbsent();
        testV2ListAbsent();
        testV1EmbeddedSCTsFromIssuedCertificate();
        testUnwrappedListRejected();
    }

    private void testV1SctRoundTrip()
    {
        SignedCertificateTimestamp original = new SignedCertificateTimestamp(
            SignedCertificateTimestamp.VERSION_V1,
            LOG_ID_32,
            TIMESTAMP,
            new byte[0],
            4, // sha256
            3, // ecdsa
            SIGNATURE_71);

        byte[] encoded = original.getEncoded();
        SignedCertificateTimestamp decoded = SignedCertificateTimestamp.getInstance(encoded);

        isEquals("v1 SCT version", SignedCertificateTimestamp.VERSION_V1, decoded.getSctVersion());
        isTrue("v1 SCT log ID", Arrays.areEqual(LOG_ID_32, decoded.getLogID()));
        isEquals("v1 SCT timestamp", TIMESTAMP, decoded.getTimestamp());
        isEquals("v1 SCT no extensions", 0, decoded.getExtensions().length);
        isEquals("v1 SCT hash alg", 4, decoded.getHashAlgorithm());
        isEquals("v1 SCT sig alg", 3, decoded.getSignatureAlgorithm());
        isTrue("v1 SCT signature", Arrays.areEqual(SIGNATURE_71, decoded.getSignature()));
        isTrue("v1 SCT round-trip bytes", Arrays.areEqual(encoded, decoded.getEncoded()));

        // Truncation must be rejected.
        try
        {
            byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
            SignedCertificateTimestamp.getInstance(truncated);
            fail("truncated v1 SCT accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void testV1ListRoundTripAndFromExtensions()
        throws Exception
    {
        SignedCertificateTimestamp sct1 = new SignedCertificateTimestamp(
            SignedCertificateTimestamp.VERSION_V1, LOG_ID_32, TIMESTAMP,
            new byte[0], 4, 3, SIGNATURE_71);

        // A second SCT with a different log ID and different signature length
        // to exercise the variable-length encoding in the list.
        byte[] altLogId = new byte[32];
        for (int i = 0; i < altLogId.length; i++)
        {
            altLogId[i] = (byte)(0xA0 + i);
        }
        byte[] sig72 = new byte[72];
        SignedCertificateTimestamp sct2 = new SignedCertificateTimestamp(
            SignedCertificateTimestamp.VERSION_V1, altLogId, TIMESTAMP + 1,
            new byte[0], 4, 3, sig72);

        SignedCertificateTimestampList list = new SignedCertificateTimestampList(
            new SignedCertificateTimestamp[]{ sct1, sct2 });

        byte[] encoded = list.getEncoded();
        SignedCertificateTimestampList decoded = SignedCertificateTimestampList.getInstance(encoded);

        isEquals("v1 list size", 2, decoded.size());
        isTrue("v1 list round-trip bytes", Arrays.areEqual(encoded, decoded.getEncoded()));

        List/*<SignedCertificateTimestamp>*/ items = decoded.getSCTs();
        isTrue("v1 first SCT log ID matches",
            Arrays.areEqual(LOG_ID_32, ((SignedCertificateTimestamp)items.get(0)).getLogID()));
        isTrue("v1 second SCT log ID matches",
            Arrays.areEqual(altLogId, ((SignedCertificateTimestamp)items.get(1)).getLogID()));

        // Now wrap in an Extensions object as it would appear in a real
        // certificate and recover via fromExtensions().
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(X509ObjectIdentifiers.id_ce_ct_embeddedSCTList, false, new DEROctetString(encoded));
        Extensions extensions = extGen.generate();

        SignedCertificateTimestampList recovered = SignedCertificateTimestampList.fromExtensions(extensions);
        isTrue("v1 fromExtensions round-trip bytes",
            Arrays.areEqual(encoded, recovered.getEncoded()));
    }

    private void testV2SctDataRoundTrip()
    {
        byte[] logId = new byte[32]; // valid: 2..127
        for (int i = 0; i < logId.length; i++)
        {
            logId[i] = (byte)i;
        }

        SctExtension ext = new SctExtension(0xABCD, new byte[]{ 0x11, 0x22, 0x33 });

        SignedCertificateTimestampDataV2 original = new SignedCertificateTimestampDataV2(
            logId, TIMESTAMP, new SctExtension[]{ ext }, SIGNATURE_71);

        byte[] encoded = original.getEncoded();
        SignedCertificateTimestampDataV2 decoded = SignedCertificateTimestampDataV2.getInstance(encoded);

        isTrue("v2 SCT log ID", Arrays.areEqual(logId, decoded.getLogID()));
        isEquals("v2 SCT timestamp", TIMESTAMP, decoded.getTimestamp());
        isEquals("v2 SCT one extension", 1, decoded.getSctExtensions().size());
        SctExtension decExt = (SctExtension)decoded.getSctExtensions().get(0);
        isEquals("v2 SCT extension type", 0xABCD, decExt.getExtensionType());
        isTrue("v2 SCT extension data", Arrays.areEqual(new byte[]{ 0x11, 0x22, 0x33 }, decExt.getExtensionData()));
        isTrue("v2 SCT signature", Arrays.areEqual(SIGNATURE_71, decoded.getSignature()));
        isTrue("v2 SCT round-trip bytes", Arrays.areEqual(encoded, decoded.getEncoded()));

        // log_id length 0 or 1 must be rejected (RFC 9162 sec. 4.8: opaque<2..127>).
        try
        {
            new SignedCertificateTimestampDataV2(new byte[1], TIMESTAMP, new SctExtension[0], SIGNATURE_71);
            fail("undersized log_id accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void testV2TransItemListRoundTripAndFromExtensions()
        throws Exception
    {
        byte[] logId = new byte[32];
        SignedCertificateTimestampDataV2 sctData = new SignedCertificateTimestampDataV2(
            logId, TIMESTAMP, new SctExtension[0], SIGNATURE_71);
        TransItem item = new TransItem(TransItem.x509_sct_v2, sctData.getEncoded());

        TransItemList list = new TransItemList(new TransItem[]{ item });

        byte[] encoded = list.getEncoded();
        TransItemList decoded = TransItemList.getInstance(encoded);

        isEquals("v2 list size", 1, decoded.size());
        isTrue("v2 list round-trip bytes", Arrays.areEqual(encoded, decoded.getEncoded()));

        TransItem decItem = (TransItem)decoded.getItems().get(0);
        isEquals("v2 item type", TransItem.x509_sct_v2, decItem.getVersionedType());

        SignedCertificateTimestampDataV2 decSct = decItem.getSignedCertificateTimestampDataV2();
        isTrue("v2 nested SCT present", decSct != null);
        isEquals("v2 nested SCT timestamp", TIMESTAMP, decSct.getTimestamp());

        // Non-SCT TransItem types must return null from the typed accessor
        // (round-trip the raw payload).
        TransItem nonSct = new TransItem(TransItem.signed_tree_head_v2, new byte[]{ 1, 2, 3, 4 });
        isTrue("non-SCT TransItem returns null SCT data",
            nonSct.getSignedCertificateTimestampDataV2() == null);

        // Now wrap in an Extensions object as it would appear in a real
        // certificate and recover via fromExtensions().
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(X509ObjectIdentifiers.id_ce_ct_transparencyInformation, false, new DEROctetString(encoded));
        Extensions extensions = extGen.generate();

        TransItemList recovered = TransItemList.fromExtensions(extensions);
        isTrue("v2 fromExtensions round-trip bytes",
            Arrays.areEqual(encoded, recovered.getEncoded()));
    }

    /**
     * RFC 6962 sec. 3.3: the SCT list in an issued certificate is an OCTET STRING nested inside the
     * extension's extnValue - github #2525.
     */
    private void testV1EmbeddedSCTsFromIssuedCertificate()
        throws Exception
    {
        Extensions extensions = new X509CertificateHolder(BC_SERVER_CERT).getExtensions();

        SignedCertificateTimestampList list = SignedCertificateTimestampList.fromExtensions(extensions);

        isEquals("issued cert SCT count", 2, list.size());

        SignedCertificateTimestamp sct1 = (SignedCertificateTimestamp)list.getSCTs().get(0);
        isEquals("issued cert SCT 1 version", 0, sct1.getSctVersion());
        isTrue("issued cert SCT 1 log ID", Arrays.areEqual(
            Hex.decode("4C63DC98E59C1DAB88F61E8A3DDEAE8FAB44A3377B5F9B94C3FBA19CFCC1BE26"), sct1.getLogID()));
        isEquals("issued cert SCT 1 timestamp", 0x000001A13912B9C1L, sct1.getTimestamp());
        isEquals("issued cert SCT 1 extensions", 0, sct1.getExtensions().length);
        isEquals("issued cert SCT 1 hash", 4, sct1.getHashAlgorithm());
        isEquals("issued cert SCT 1 signature", 3, sct1.getSignatureAlgorithm());

        SignedCertificateTimestamp sct2 = (SignedCertificateTimestamp)list.getSCTs().get(1);
        isTrue("issued cert SCT 2 log ID", Arrays.areEqual(
            Hex.decode("A2810018734E176E1D47E09540F381BA546697CD63A84350716EB8094EDAF10D"), sct2.getLogID()));
        isEquals("issued cert SCT 2 timestamp", 0x000001A13912BC86L, sct2.getTimestamp());
        isTrue("issued cert SCT 2 extensions", Arrays.areEqual(Hex.decode("0000050023558B5F"), sct2.getExtensions()));

        // re-encoding and re-wrapping reproduces the issued extension value exactly
        byte[] extnValue = extensions.getExtension(X509ObjectIdentifiers.id_ce_ct_embeddedSCTList).getExtnValue().getOctets();
        isTrue("issued cert SCT list re-encoding", Arrays.areEqual(extnValue, new DEROctetString(list.getEncoded()).getEncoded()));
    }

    /**
     * A bare TLS list placed directly in extnValue, without the inner OCTET STRING the RFCs require, is
     * not accepted.
     */
    private void testUnwrappedListRejected()
        throws Exception
    {
        SignedCertificateTimestamp sct = new SignedCertificateTimestamp(
            SignedCertificateTimestamp.VERSION_V1, LOG_ID_32, TIMESTAMP, new byte[0], 4, 3, SIGNATURE_71);
        byte[] v1List = new SignedCertificateTimestampList(new SignedCertificateTimestamp[]{ sct }).getEncoded();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(X509ObjectIdentifiers.id_ce_ct_embeddedSCTList, false, v1List);
        try
        {
            SignedCertificateTimestampList.fromExtensions(extGen.generate());
            fail("v1 list without the inner OCTET STRING accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        TransItem item = new TransItem(TransItem.x509_sct_v2, new SignedCertificateTimestampDataV2(
            new byte[32], TIMESTAMP, new SctExtension[0], SIGNATURE_71).getEncoded());
        byte[] v2List = new TransItemList(new TransItem[]{ item }).getEncoded();

        extGen = new ExtensionsGenerator();
        extGen.addExtension(X509ObjectIdentifiers.id_ce_ct_transparencyInformation, false, v2List);
        try
        {
            TransItemList.fromExtensions(extGen.generate());
            fail("v2 list without the inner OCTET STRING accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void testV1ListAbsent()
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false));
        Extensions noV1 = extGen.generate();

        isTrue("absent v1 extension yields null",
            SignedCertificateTimestampList.fromExtensions(noV1) == null);
        isTrue("null extensions yields null (v1)",
            SignedCertificateTimestampList.fromExtensions(null) == null);
    }

    private void testV2ListAbsent()
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false));
        Extensions noV2 = extGen.generate();

        isTrue("absent v2 extension yields null",
            TransItemList.fromExtensions(noV2) == null);
        isTrue("null extensions yields null (v2)",
            TransItemList.fromExtensions(null) == null);
    }

    public static void main(String[] args)
    {
        runTest(new CertificateTransparencyTest());
    }
}
