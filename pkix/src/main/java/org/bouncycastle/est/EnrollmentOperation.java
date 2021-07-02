package org.bouncycastle.est;

public enum EnrollmentOperation {
    SIMPLE_ENROLL(ESTService.SIMPLE_ENROLL),
    SIMPLE_REENROLL(ESTService.SIMPLE_REENROLL),
    SERVERGEN(ESTService.SERVERGEN);

    public String getUriPart() {
        return uriPart;
    }

    private final String uriPart;

    EnrollmentOperation(String uriPart) {
        this.uriPart = uriPart;
    }
}
