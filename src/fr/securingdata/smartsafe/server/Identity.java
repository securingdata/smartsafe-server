package fr.securingdata.smartsafe.server;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public abstract class Identity implements Constants {
	Identity next;
	protected byte[] identifier;
	
	protected Identity() {}
	
	public void clear() {
		Util.arrayFillNonAtomic(identifier, ZERO, (short) identifier.length, ZERO);
		identifier = null;
		next = null;
		JCSystem.requestObjectDeletion();
	}
	public byte getIdentifier(byte[] out, short outOffset) {
		byte i;
		for (i = 0; i < identifier.length && identifier[i] != 0; i++)
			out[(short) (outOffset + i)] = identifier[i];
		return i;
	}
	public void setIdentifier(byte[] in, short inOffset, short inLen) {
		if (identifier == null || identifier.length != inLen) {
			if (identifier != null)
				JCSystem.requestObjectDeletion();
			identifier = new byte[inLen];
		}
		Util.arrayCopy(in, inOffset, identifier, ZERO, inLen);
	}
	public boolean isEqual(byte[] cmp, short cmpOffset, short cmpLen) {
		if (identifier.length != cmpLen)
			return false;
		return Util.arrayCompare(identifier, ZERO, cmp, cmpOffset, cmpLen) == 0;
	}
}
