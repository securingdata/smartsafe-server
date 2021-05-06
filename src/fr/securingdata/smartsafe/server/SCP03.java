package fr.securingdata.smartsafe.server;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*;

public class SCP03 implements /*SecureChannel,*/ Constants {
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
		
		kMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		kEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		sMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		sEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		sRMac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
	}
	
	public void setKeys(byte[] buffer, short offset) {
		kEnc.setKey(buffer, offset);
		kMac.setKey(buffer, (short) (offset + 16));
	}
	
	private boolean isAuthenticated() {
		return status[ZERO] == STATUS_AUTHENTICATED;
	}
	private void error() {
		resetSecurity();
		ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}
	private void initUpdate(APDU apdu) {
		resetSecurity();
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
	private void externalAuth(APDU apdu) {
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

	/*
	 * SecureChannel interface methods
	 * */
	public short decryptData(byte[] buffer, short offset, short len) throws ISOException {
		ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);//Decryption with KDEK not supported
		return 0;//Dead code only for the compiler
	}
	public short encryptData(byte[] buffer, short offset, short len) throws ArrayIndexOutOfBoundsException {
		ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);//Encryption with KDEK not supported
		return 0;//Dead code only for the compiler
	}

	public byte getSecurityLevel() {
		if (isAuthenticated()) {//Only one mode is supported in External Authenticate command
			return (byte) 0xB3;//(AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION);
		}
		return ZERO;//NO_SECURITY_LEVEL;
	}

	public short processSecurity(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		
		switch(Util.getShort(buffer, ISO7816.OFFSET_CLA)) {
			case CLA_INS_INIT_UPDATE:
				initUpdate(apdu);
				break;
			case CLA_INS_EXT_AUTH:
				externalAuth(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		return 0;
	}

	public void resetSecurity() {
		status[ZERO] = STATUS_RESET;
		Util.arrayFillNonAtomic(macChaining, ZERO, (short) macChaining.length, ZERO);
		Util.arrayFillNonAtomic(encryptionCounter, ZERO, (short) encryptionCounter.length, ZERO);
	}

	public short unwrap(byte[] buffer, short offset, short lc) throws ISOException {
		//offset is always set to 0 in SmartSafe context
		
		if (status[ZERO] != STATUS_AUTHENTICATED)
			error();
		
		//Remove MAC
		checkMac(buffer, lc);
		lc -= 8;
		
		//Decrypt data
		incrementEncryptionCounter();
		encryptionCounter[ZERO] = ZERO;
		aesCBC.init(sEnc, Cipher.MODE_ENCRYPT);
		aesCBC.doFinal(encryptionCounter, ZERO, (short) 16, workingArray, ZERO);
		aesCBC.init(sEnc, Cipher.MODE_DECRYPT, workingArray, ZERO, (short) 16);
		aesCBC.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, buffer, ISO7816.OFFSET_CDATA);
		
		//Remove padding
		while(buffer[(short) (ISO7816.OFFSET_CDATA + lc - 1)] == ZERO)
			lc--;
		if (buffer[(short) (ISO7816.OFFSET_CDATA + lc - 1)] != (byte) 0x80)
			error();
		lc--;
		buffer[(short) 4] = (byte) lc;
		
		return lc;
	}

	public short wrap(byte[] buffer, short offset, short len) throws ArrayIndexOutOfBoundsException, ISOException {
		//offset is always set to 0 in SmartSafe context
		
		if (status[ZERO] != STATUS_AUTHENTICATED)
			error();
		
		//Extract status word
		len -= 2;
		short sw = Util.getShort(buffer, len);
		
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
		
		return (short) (len + 8);
	}
}
