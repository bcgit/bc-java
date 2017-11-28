package org.bouncycastle.tls;

import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class TokenBindingExtension {

    public static final Integer rsa2048_pcks15 = 0;
    public static final Integer rsa2048_pss = 1;
    public static final Integer rsa2048_ecdsap256 = 2;

    List<Integer> TokenBindingKeyParameters = new ArrayList<Integer>();

    private   static int MajorProtocolVerison=0;

    public static int getMajorProtocolVerison() {
        return MajorProtocolVerison;
    }

    public static int getMinorProtocolVerison() {
        return MinorProtocolVerison;
    }

    private   static int MinorProtocolVerison=13;

    public static void setMajorProtocolVerison(int majorProtocolVerison) {
        MajorProtocolVerison = majorProtocolVerison;
    }

    public static void setMinorProtocolVerison(int minorProtocolVerison) {
        MinorProtocolVerison = minorProtocolVerison;
    }

    public void addTokenbindingKeyParameters(int parameter){
        TokenBindingKeyParameters.add(parameter);
    }

    public List<Integer> getTokenBindingKeyParameters() {
        if (TokenBindingKeyParameters.size() <1){
            TokenBindingKeyParameters.add(rsa2048_pcks15);
        }
        Collections.sort(TokenBindingKeyParameters,Collections.reverseOrder());
        return TokenBindingKeyParameters;
    }

    public void encode (OutputStream output) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        TlsUtils.checkUint8(MajorProtocolVerison);
        TlsUtils.checkUint8(MinorProtocolVerison);
        TlsUtils.writeUint8(MajorProtocolVerison,output);
        TlsUtils.writeUint8(MinorProtocolVerison,output);

        for (Integer param : this.getTokenBindingKeyParameters()){
            TlsUtils.checkUint8(param);
            TlsUtils.writeUint8(param,buf);
        }

        TlsUtils.checkUint8(buf.size());
        TlsUtils.writeUint8(buf.size(), output);
        Streams.writeBufTo(buf, output);

    }

}
