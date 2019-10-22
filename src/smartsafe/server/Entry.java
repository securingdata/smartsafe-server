package smartsafe.server;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Entry extends Identity {
	private Object[] data;
	
	public Entry(byte nbData) {
		data = new Object[nbData];
	}
	
	public void clear() {
		super.clear();
		short i;
		for (i = ZERO; i < data.length; i++) {
			if (data[i] != null) {
				byte[] tmp = (byte[]) data[i];
				Util.arrayFillNonAtomic(tmp, ZERO, (short) tmp.length, ZERO);
			}
		}
	}
	public short getNbData() {
		return (short) data.length;
	}
	public short getData(byte index, byte[] out, short outOffset) {
		byte[] tmp = (byte[]) data[index];
		if (tmp == null)
			return ZERO;
		Util.arrayCopyNonAtomic(tmp, ZERO, out, outOffset, (short) tmp.length);
		return (short) tmp.length;
	}
	public void setData(byte index, byte[] in, short inOffset, short length) {
		byte[] tmp = (byte[]) data[index];
		if (tmp == null || tmp.length != length) {
			if (tmp != null)
				JCSystem.requestObjectDeletion();
			data[index] = tmp = new byte[length];
		}
		Util.arrayCopy(in, inOffset, tmp, ZERO, (short) tmp.length);
	}
}
