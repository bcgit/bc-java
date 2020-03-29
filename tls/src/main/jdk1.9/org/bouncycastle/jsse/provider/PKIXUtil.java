package org.bouncycastle.jsse.provider;

import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Map;

abstract class PKIXUtil
{
    static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters,
        Map<X509Certificate, byte[]> statusResponseMap)
    {
        JsseUtils_8.addStatusResponses(pkixBuilder, pkixParameters, statusResponseMap);
    }
}
