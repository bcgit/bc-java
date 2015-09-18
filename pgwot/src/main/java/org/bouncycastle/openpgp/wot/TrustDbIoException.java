package org.bouncycastle.openpgp.wot;

public class TrustDbIoException extends TrustDbException {
	private static final long serialVersionUID = 1L;

	public TrustDbIoException() {
	}

	public TrustDbIoException(String message) {
		super(message);
	}

	public TrustDbIoException(Throwable cause) {
		super(cause);
	}

	public TrustDbIoException(String message, Throwable cause) {
		super(message, cause);
	}
}
