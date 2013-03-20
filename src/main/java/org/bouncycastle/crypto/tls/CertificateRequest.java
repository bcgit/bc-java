package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;

public class CertificateRequest {
    private short[] certificateTypes;
    private Vector certificateAuthorities;

    public CertificateRequest(short[] certificateTypes, Vector certificateAuthorities) {
        this.certificateTypes = certificateTypes;
        this.certificateAuthorities = certificateAuthorities;
    }

    public short[] getCertificateTypes() {
        return certificateTypes;
    }

    /**
     * @return Vector of X500Name
     */
    public Vector getCertificateAuthorities() {
        return certificateAuthorities;
    }

    public void encode(OutputStream output) throws IOException {

        if (certificateTypes == null || certificateTypes.length == 0) {
            TlsUtils.writeUint8((short) 0, output);
        } else {
            TlsUtils.writeUint8((short) certificateTypes.length, output);
            TlsUtils.writeUint8Array(certificateTypes, output);
        }

        if (certificateAuthorities == null || certificateAuthorities.isEmpty()) {
            TlsUtils.writeUint16(0, output);
        } else {

            Vector encDNs = new Vector(certificateAuthorities.size());
            int totalLength = 0;
            for (int i = 0; i < certificateAuthorities.size(); ++i) {
                X500Name authorityDN = (X500Name) certificateAuthorities.get(i);
                byte[] encDN = authorityDN.getEncoded(ASN1Encoding.DER);
                encDNs.addElement(encDN);
                totalLength += encDN.length;
            }

            TlsUtils.writeUint16(totalLength, output);

            for (int i = 0; i < encDNs.size(); ++i) {
                byte[] encDN = (byte[]) encDNs.elementAt(i);
                output.write(encDN);
            }
        }
    }

    public static CertificateRequest parse(InputStream input) throws IOException {
        int numTypes = TlsUtils.readUint8(input);
        short[] certificateTypes = new short[numTypes];
        for (int i = 0; i < numTypes; ++i) {
            certificateTypes[i] = TlsUtils.readUint8(input);
        }

        byte[] authorities = TlsUtils.readOpaque16(input);

        Vector authorityDNs = new Vector();

        ByteArrayInputStream bis = new ByteArrayInputStream(authorities);
        while (bis.available() > 0) {
            byte[] dnBytes = TlsUtils.readOpaque16(bis);
            authorityDNs.addElement(X500Name.getInstance(ASN1Primitive.fromByteArray(dnBytes)));
        }

        return new CertificateRequest(certificateTypes, authorityDNs);
    }
}
