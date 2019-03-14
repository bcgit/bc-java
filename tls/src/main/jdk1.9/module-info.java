module org.bouncycastle.tls
{
    provides java.security.Provider with org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
    
    requires java.logging;
    requires org.bouncycastle.provider;
    
    exports org.bouncycastle.jsse;
    exports org.bouncycastle.tls;
    exports org.bouncycastle.jsse.provider;
    exports org.bouncycastle.jsse.java.security;
    exports org.bouncycastle.tls.crypto;
    exports org.bouncycastle.tls.crypto.impl;
    exports org.bouncycastle.tls.crypto.impl.bc;
    exports org.bouncycastle.tls.crypto.impl.jcajce;
    exports org.bouncycastle.tls.crypto.impl.jcajce.srp;
}
