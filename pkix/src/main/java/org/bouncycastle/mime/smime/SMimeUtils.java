package org.bouncycastle.mime.smime;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;

class SMimeUtils
{


    public static final Map RFC5751_MICALGS;
    public static final Map RFC3851_MICALGS;
    public static final Map STANDARD_MICALGS;
    public static final Map forMic;

    public static final byte[] nl = new byte[2];


    static
    {
        nl[0] = '\r';
        nl[1] = '\n';


        Map stdMicAlgs = new HashMap();

        stdMicAlgs.put(CMSAlgorithm.MD5, "md5");
        stdMicAlgs.put(CMSAlgorithm.SHA1, "sha-1");
        stdMicAlgs.put(CMSAlgorithm.SHA224, "sha-224");
        stdMicAlgs.put(CMSAlgorithm.SHA256, "sha-256");
        stdMicAlgs.put(CMSAlgorithm.SHA384, "sha-384");
        stdMicAlgs.put(CMSAlgorithm.SHA512, "sha-512");
        stdMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

        RFC5751_MICALGS = Collections.unmodifiableMap(stdMicAlgs);

        Map oldMicAlgs = new HashMap();

        oldMicAlgs.put(CMSAlgorithm.MD5, "md5");
        oldMicAlgs.put(CMSAlgorithm.SHA1, "sha1");
        oldMicAlgs.put(CMSAlgorithm.SHA224, "sha224");
        oldMicAlgs.put(CMSAlgorithm.SHA256, "sha256");
        oldMicAlgs.put(CMSAlgorithm.SHA384, "sha384");
        oldMicAlgs.put(CMSAlgorithm.SHA512, "sha512");
        oldMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");


        RFC3851_MICALGS = Collections.unmodifiableMap(oldMicAlgs);

        STANDARD_MICALGS = RFC5751_MICALGS;


        Map<String, ASN1ObjectIdentifier> mic = new TreeMap<String, ASN1ObjectIdentifier>(String.CASE_INSENSITIVE_ORDER);

        for (Object key : STANDARD_MICALGS.keySet())
        {
            mic.put(STANDARD_MICALGS.get(key).toString(), (ASN1ObjectIdentifier)key);
        }

        for (Object key : RFC3851_MICALGS.keySet())
        {
            mic.put(RFC3851_MICALGS.get(key).toString(), (ASN1ObjectIdentifier)key);
        }

        forMic = Collections.unmodifiableMap(mic);

    }
}
