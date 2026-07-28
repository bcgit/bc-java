// NOTE: bctls-klog replacement for tls/src/main/jdk1.9/module-info.java. The module name is
// deliberately unchanged, so that this jar drops straight in where bctls was; the one difference is
// the exported org.bouncycastle.tls.keylog. Keep the rest in step with the tls original.
module org.bouncycastle.tls
{
    provides java.security.Provider with org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

    requires java.logging;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.util;

    exports org.bouncycastle.jsse;
    exports org.bouncycastle.tls;
    exports org.bouncycastle.tls.keylog;
    exports org.bouncycastle.jsse.provider;
    exports org.bouncycastle.jsse.java.security;
    exports org.bouncycastle.jsse.util;
    exports org.bouncycastle.tls.crypto;
    exports org.bouncycastle.tls.crypto.impl;
    exports org.bouncycastle.tls.crypto.impl.bc;
    exports org.bouncycastle.tls.crypto.impl.jcajce;
    exports org.bouncycastle.tls.crypto.impl.jcajce.srp;
}
