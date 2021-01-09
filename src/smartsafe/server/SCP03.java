package smartsafe.server;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class SCP03 implements Constants {
	private static final byte STATUS_RESET         = (byte) 0x00;
	private static final byte STATUS_INITIATED     = (byte) 0x01;
	private static final byte STATUS_AUTHENTICATED = (byte) 0x02;
	
	private static final byte DERIVATION_DATA_OFFSET = 32;
	private static final byte DERIVATION_DATA_HOST_CHALL_OFFSET = (byte) (DERIVATION_DATA_OFFSET + 16);
	private static final byte DERIVATION_DATA_CARD_CHALL_OFFSET = (byte) (DERIVATION_DATA_OFFSET + 16 + 8);
	
	private static final byte CARD_CRYPTO_DERIVATION_CSTE = 0x00;
	private static final byte HOST_CRYPTO_DERIVATION_CSTE = 0x01;
	private static final byte SENC_DERIVATION_CSTE        = 0x04;
	private static final byte SMAC_DERIVATION_CSTE        = 0x06;
	private static final byte RMAC_DERIVATION_CSTE        = 0x07;
	
	private byte[] status;
	private byte[] workingArray;
	private byte[] macChaining, encryptionCounter;
	private RandomData random;
	private Signature aesCMac;
	private Cipher aesCBC;
	private AESKey kMac, kEnc, sMac, sEnc, sRMac;
	
	public SCP03() {
		status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		workingArray = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
		macChaining = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		encryptionCounter = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		aesCMac = new AESCMac128();
		aesCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		
		kMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
		kEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
		sMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
		sEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
		sRMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
	}
	
	public void setKeys(byte[] buffer, short offset) {
		kEnc.setKey(buffer, offset);
		kMac.setKey(buffer, (short) (offset + 16));
	}
	
	public boolean isAuthenticated() {
		return status[ZERO] == STATUS_AUTHENTICATED;
	}
	public void reset() {
		status[ZERO] = STATUS_RESET;
		Util.arrayFillNonAtomic(macChaining, ZERO, (short) macChaining.length, ZERO);
		Util.arrayFillNonAtomic(encryptionCounter, ZERO, (short) encryptionCounter.length, ZERO);
	}
	public void error() {
		reset();
		ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}
	public void initUpdate(APDU apdu) {
		reset();
		byte[] buffer = apdu.getBuffer();
		if (apdu.setIncomingAndReceive() != 8)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		Util.arrayFillNonAtomic(workingArray, DERIVATION_DATA_OFFSET, (short) 16, ZERO);
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, workingArray, DERIVATION_DATA_HOST_CHALL_OFFSET, (byte) 8);
		random.generateData(workingArray, DERIVATION_DATA_CARD_CHALL_OFFSET, (short) 8);
		computeSessionKeys();
		
		computeDerivationScheme(CARD_CRYPTO_DERIVATION_CSTE);
		aesCMac.init(sMac, Signature.MODE_SIGN);
		aesCMac.sign(workingArray, DERIVATION_DATA_OFFSET, (short) 32, workingArray, ZERO);
		
		//Response
		Util.arrayFillNonAtomic(buffer, ZERO, (short) 10, ZERO);
		buffer[(short) 10] = ZERO;//KVN
		buffer[(short) 11] = (byte) 0x03;//SCP
		buffer[(short) 12] = (byte) 0x60;//i
		Util.arrayCopyNonAtomic(workingArray, DERIVATION_DATA_CARD_CHALL_OFFSET, buffer, (short) 13, (byte) 8);
		Util.arrayCopyNonAtomic(workingArray, ZERO/*Card crypto offset*/, buffer, (short) 21, (byte) 8);
		apdu.setOutgoingAndSend(ZERO, (short) 29);
		
		status[ZERO] = STATUS_INITIATED;
	}
	public void externalAuth(APDU apdu) {
		if (status[ZERO] != STATUS_INITIATED)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		byte[] buffer = apdu.getBuffer();
		if (buffer[ISO7816.OFFSET_P1] != 0x33)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		if (apdu.setIncomingAndReceive() != 16)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		computeDerivationScheme(HOST_CRYPTO_DERIVATION_CSTE);
		aesCMac.init(sMac, Signature.MODE_SIGN);
		aesCMac.sign(workingArray, DERIVATION_DATA_OFFSET, (short) 32, workingArray, ZERO);
		if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, workingArray, ZERO, (short) 8) != 0)
			error();
		checkMac(buffer, (short) 16);
		
		status[ZERO] = STATUS_AUTHENTICATED;
	}
	public short unwrap(APDU apdu) {
		if (status[ZERO] != STATUS_AUTHENTICATED)
			error();
		byte[] buffer = apdu.getBuffer();
		short lc = apdu.setIncomingAndReceive();
		
		checkMac(buffer, lc);
		lc -= 8;
		
		incrementEncryptionCounter();
		encryptionCounter[ZERO] = ZERO;
		aesCBC.init(sEnc, Cipher.MODE_ENCRYPT);
		aesCBC.doFinal(encryptionCounter, ZERO, (short) 16, workingArray, ZERO);
		aesCBC.init(sEnc, Cipher.MODE_DECRYPT, workingArray, ZERO, (short) 16);
		aesCBC.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, buffer, ISO7816.OFFSET_CDATA);
		
		
		while(buffer[(short) (ISO7816.OFFSET_CDATA + lc - 1)] == ZERO)
			lc--;
		if (buffer[(short) (ISO7816.OFFSET_CDATA + lc - 1)] != (byte) 0x80)
			error();
		lc--;
		buffer[(short) 4] = (byte) lc;
		
		return lc;
	}
	public void wrap(APDU apdu) {
		wrap(apdu, ZERO);
	}
	public void wrap(APDU apdu, short len) {
		wrap(apdu, len, ISO7816.SW_NO_ERROR);
	}
	public void wrap(APDU apdu, short len, short sw) {
		if (status[ZERO] != STATUS_AUTHENTICATED)
			error();
		
		byte[] buffer = apdu.getBuffer();
		
		//Add padding
		buffer[len] = (byte) 0x80;
		len++;
		while (len % 16 != 0) {
			buffer[len] = ZERO;
			len++;
		}
		
		incrementEncryptionCounter();
		encryptionCounter[ZERO] = (byte) 0x80;
		aesCBC.init(sEnc, Cipher.MODE_ENCRYPT);
		aesCBC.doFinal(encryptionCounter, ZERO, (short) 16, workingArray, ZERO);
		aesCBC.init(sEnc, Cipher.MODE_ENCRYPT, workingArray, ZERO, (short) 16);
		aesCBC.doFinal(buffer, ZERO, len, buffer, ZERO);
		Util.setShort(buffer, len, sw);
		
		aesCMac.init(sRMac, Signature.MODE_SIGN);
		aesCMac.update(macChaining, ZERO, (short) 16);
		aesCMac.sign(buffer, ZERO, (short) (len + 2), buffer, len);
		
		apdu.setOutgoingAndSend(ZERO, (short) (len + 8));
		ISOException.throwIt(sw);
	}
	
	private void incrementEncryptionCounter() {
		for (short s = (short) (encryptionCounter.length - 1); s >= 0; s--) {
			encryptionCounter[s]++;
			if(encryptionCounter[s] != 0)
				return;
		}
	}
	private void checkMac(byte[] buffer, short dataLen) {
		aesCMac.init(sMac, Signature.MODE_SIGN);
		aesCMac.update(macChaining, ZERO, (short) 16);
		aesCMac.sign(buffer, ZERO, (short) (5 + dataLen - 8), macChaining, ZERO);
		if (Util.arrayCompare(buffer, (short) (5 + dataLen - 8), macChaining, ZERO, (short) 8) != 0)
			error();
	}
	private void computeSessionKeys() {
		computeDerivationScheme(SENC_DERIVATION_CSTE);
		aesCMac.init(kEnc, Signature.MODE_SIGN);
		aesCMac.sign(workingArray, DERIVATION_DATA_OFFSET, (short) 32, workingArray, (short) 0);
		sEnc.setKey(workingArray, (short) 0);
		
		computeDerivationScheme(SMAC_DERIVATION_CSTE);
		aesCMac.init(kMac, Signature.MODE_SIGN);
		aesCMac.sign(workingArray, DERIVATION_DATA_OFFSET, (short) 32, workingArray, (short) 0);
		sMac.setKey(workingArray, (short) 0);
		
		computeDerivationScheme(RMAC_DERIVATION_CSTE);
		aesCMac.init(kMac, Signature.MODE_SIGN);
		aesCMac.sign(workingArray, DERIVATION_DATA_OFFSET, (short) 32, workingArray, (short) 0);
		sRMac.setKey(workingArray, (short) 0);
	}
	private void computeDerivationScheme(byte derivationCste) {
		workingArray[(short) (DERIVATION_DATA_OFFSET + 11)] = derivationCste;
		
		switch(derivationCste) {
			case CARD_CRYPTO_DERIVATION_CSTE:
			case HOST_CRYPTO_DERIVATION_CSTE:
				workingArray[(short) (DERIVATION_DATA_OFFSET + 13)] = (byte) 0x00;
				workingArray[(short) (DERIVATION_DATA_OFFSET + 14)] = (byte) 0x40;
				workingArray[(short) (DERIVATION_DATA_OFFSET + 15)] = (byte) 0x01;
				break;
			case SENC_DERIVATION_CSTE:
			case SMAC_DERIVATION_CSTE:
			case RMAC_DERIVATION_CSTE:
				workingArray[(short) (DERIVATION_DATA_OFFSET + 13)] = (byte) 0x00;
				workingArray[(short) (DERIVATION_DATA_OFFSET + 14)] = (byte) 0x80;
				workingArray[(short) (DERIVATION_DATA_OFFSET + 15)] = (byte) 0x01;
				break;
		}
	}
}
