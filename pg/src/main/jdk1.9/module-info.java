module org.bouncycastle.pg
{
    requires org.bouncycastle.provider;
    requires org.bouncycastle.util;
    requires java.logging;

    exports org.bouncycastle.bcpg;
    exports org.bouncycastle.gpg;
    exports org.bouncycastle.openpgp;
    exports org.bouncycastle.bcpg.attr;
    exports org.bouncycastle.bcpg.sig;
    exports org.bouncycastle.gpg.keybox;
    exports org.bouncycastle.gpg.keybox.bc;
    exports org.bouncycastle.gpg.keybox.jcajce;
    exports org.bouncycastle.openpgp.api;
    exports org.bouncycastle.openpgp.api.bc;
    exports org.bouncycastle.openpgp.api.jcajce;
    exports org.bouncycastle.openpgp.bc;
    exports org.bouncycastle.openpgp.examples;
    exports org.bouncycastle.openpgp.jcajce;
    exports org.bouncycastle.openpgp.operator;
    exports org.bouncycastle.openpgp.operator.bc;
    exports org.bouncycastle.openpgp.operator.jcajce;
}
