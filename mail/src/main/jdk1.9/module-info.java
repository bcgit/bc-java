module org.bouncycastle.mail
{
    requires org.bouncycastle.provider;
    requires transitive org.bouncycastle.pkix;
    requires java.datatransfer;
    requires org.bouncycastle.util;

    // optional: javax.mail/javax.activation go by these four names depending on the artifact used, a hard requires on any one of them breaks the rest.
    requires static mail;
    requires static java.mail;
    requires static activation;
    requires static java.activation;

    exports org.bouncycastle.mail.smime;
    exports org.bouncycastle.mail.smime.handlers;
    exports org.bouncycastle.mail.smime.util;
    exports org.bouncycastle.mail.smime.validator;
}
