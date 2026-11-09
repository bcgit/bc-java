/**
 * NOTE: org.bouncycastle.openpgp.smartcard.yubikey is compiled against YubiKit but YubiKit is not a
 * dependency of this module, matching the optional com.yubico.* import in the OSGi manifest. YubiKit's
 * jars carry no module names, so a requires on them would bind to names derived from their file names.
 * To use the YubiKey backend from the module path, put YubiKit on the class path and add
 * --add-reads org.bouncycastle.pgsc=ALL-UNNAMED. The rest of the module needs nothing extra.
 */
module org.bouncycastle.pgsc
{
    requires org.bouncycastle.provider;
    requires org.bouncycastle.util;
    requires org.bouncycastle.pg;

    exports org.bouncycastle.openpgp.smartcard;
    exports org.bouncycastle.openpgp.smartcard.card;
    exports org.bouncycastle.openpgp.smartcard.operator;
    exports org.bouncycastle.openpgp.smartcard.operator.bc;
    exports org.bouncycastle.openpgp.smartcard.operator.jcajce;
    exports org.bouncycastle.openpgp.smartcard.simulator;
    exports org.bouncycastle.openpgp.smartcard.yubikey;
}
