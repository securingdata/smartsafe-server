package fr.securingdata.smartsafe.server;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;

public class SmartSafe extends Applet implements Constants {
	private static final byte[] version = {'2', '.', '1', '.', '0'};
	private SCP03 scp;
	private OwnerPIN pin;
	private RandomData random;
	private byte[] transactionBuffer;
	
	private List groups;
	private Object[] selection;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new SmartSafe().register();
	}
	
	public SmartSafe() {
		scp = new SCP03();
		groups = new List();
		transactionBuffer = new byte[TRNS_BUFF_MAX_SIZE];
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		selection = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
	}
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		short clains = Util.getShort(buffer, ISO7816.OFFSET_CLA);
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		short lc = 0;
		Group selectedGroup = (Group) selection[GROUP_INDEX], tmp;
		Entry selectedEntry = (Entry) selection[ENTRY_INDEX];
		
		/* * * * * * * * * * * * * * * * * * * * * * * 
		 *                                           *
		 * Dispatch commands without authentication  *
		 *                                           *
		 * 1. Select                                 *
		 * 2. Get Version                            *
		 * 3. Initialize PIN                         *
		 * 4. Manage Transaction                     *
		 *                                           *
		 * * * * * * * * * * * * * * * * * * * * * * */
		
		/**
		 * Standard Select.
		 * 
		 * input: the applet AID.
		 * output: life cycle state coded as follows:
		 * 			- 0xDECA -> the user PIN has not been initialized yet
		 * 			- 0xCAFE -> the user PIN has been initialized
		 * 			- 0xDEAD -> the user PIN is blocked (PTC value is 0), the applet cannot be used anymore
		 * */
		if (selectingApplet()) {
			if (pin != null) {
				if (pin.getTriesRemaining() != 0)
					Util.setShort(buffer, ZERO, (short) 0xCAFE);
				else
					Util.setShort(buffer, ZERO, (short) 0xDEAD);
			}
			else {
				Util.setShort(buffer, ZERO, (short) 0xDECA);
			}
			apdu.setOutgoingAndSend(ZERO, (short) 2);
			return;
		}
		
		/**
		 * Return the version of the applet.
		 * 
		 * input: none
		 * output: the version in a string format
		 * */
		if (clains == CLA_INS_GET_VERSION) {
			Util.arrayCopyNonAtomic(version, ZERO, buffer, ZERO, (short) version.length);
			apdu.setOutgoingAndSend(ZERO, (short) version.length);
			return;
		}
		
		/**
		 * Initialize the user PIN.
		 * 
		 * input: see #changePin(byte[], short)
		 * output: none
		 * */
		if (pin == null && clains == CLA_INS_INIT_PIN) {
			lc = apdu.setIncomingAndReceive();
			if (p1 != 0 || p2 != 0)
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			if (lc > PIN_DATA_MAX_SIZE)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			initChangePin(buffer, lc);
			commitChangePin();
			return;
		}
		
		/**
		 * Manage and return the Transaction status related to PIN update.
		 * 
		 * input: p1 (only if a transaction is on progress)
		 * 			00 -> do nothing
		 * 			01 -> abort
		 * 			02 -> commit
		 * 
		 * output: the transaction status
		 * 			00 -> no transaction
		 * 			01 -> a transaction is on-going
		 * */
		if (clains == CLA_INS_MANAGE_TRNS) {
			if (transactionBuffer[TRNS_BUFF_STATUS_OFFSET] == STATUS_ON) {
				if (p1 == (byte) 1)
					abortChangePin();
				else if (p1 == (byte) 2)
					commitChangePin();
			}
			
			buffer[0] = transactionBuffer[TRNS_BUFF_STATUS_OFFSET];
			apdu.setOutgoingAndSend(ZERO, (short) 1);
			return;
		}
		
		/* * * * * * * * * * * * * * * * * * * * * * 
		 *                                         *
		 * End of commands without authentication  *
		 *                                         *
		 * * * * * * * * * * * * * * * * * * * * * */
		
		//At this state, if PIN is not initialized, throw Exception
		if (pin == null)
			ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
		
		/* * * * * * * * * * * * 
		 *                     *
		 * User authentication *
		 *                     *
		 * * * * * * * * * * * */
		
		switch (clains) {
			
			/**
			 * See GlobalPlatform specifications.
			 * */
			case CLA_INS_INIT_UPDATE:
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, scp.processSecurity(apdu));
				return;
			
			/**
			 * See GlobalPlatform specifications.
			 * */
			case CLA_INS_EXT_AUTH:
				try {
					scp.processSecurity(apdu);
				} catch (ISOException e) {
					pin.check(buffer, ZERO, (byte) 1);//Force PTC decreasing
					ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
				}
				return;
				
			/**
			 * Verify the user PIN.
			 * 
			 * input: the PIN value
			 * output: if the submitted PIN is correct, none
			 *         if the submitted PIN is incorrect, the value of the PIN try counter (PTC)
			 * */
			case CLA_SEC_INS_AUTHENTICATE:
				lc = scp.unwrap(buffer, ZERO, apdu.setIncomingAndReceive());
				if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) lc)) {
					wrapOk(apdu, buffer);
					return;
				}
				ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
			default:
				//Fall through main dispatcher
		}
		
		/* * * * * * * * * * * * * * * * 
		 *                             *
		 * End of user authentication  *
		 *                             *
		 * * * * * * * * * * * * * * * */
		
		//At this state, if user is not authenticated, throw Exception
		if (scp.getSecurityLevel() == 0 || !pin.isValidated())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		//Only command with CLA_SECURED (0x84) must be unwrapped
		if ((byte) (clains >> 8) == CLA_SECURED)
			lc = scp.unwrap(buffer, ZERO, apdu.setIncomingAndReceive());
		
		/* * * * * * * * * * * * * * * 
		 *                           *
		 * Main commands dispatcher  *
		 *                           *
		 * * * * * * * * * * * * * * */
		
		//"State machine" checks
		switch (clains) {
			case CLA_INS_GET_DATA:
			case CLA_INS_SET_DATA:
				//Index FF -> identifier -> only authorized under SM with CLA_SEC
				//Index 0 -> password -> only authorized under SM with CLA_SEC
				if (p1 <= 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				//Fall through
			case CLA_SEC_INS_GET_DATA:
				if (p1 < 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			case CLA_SEC_INS_SET_DATA:
				if (p1 < -1 || p1 >= selectedEntry.getNbData() || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				//Fall through
			case CLA_INS_MOVE_ENTRY:
				if (selectedEntry == null)
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				//Fall through
			case CLA_INS_GET_STATS:
			case CLA_INS_RENAME_GROUP:
			case CLA_INS_MOVE_GROUP:
			case CLA_SEC_INS_ADD_ENTRY:
			case CLA_SEC_INS_DELETE_ENTRY:
			case CLA_SEC_INS_LIST_ENTRIES:
			case CLA_SEC_INS_SELECT_ENTRY:
				if (selectedGroup == null)
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			default:
				//Fall through
		}
		
		//Main dispatcher
		switch (clains) {
			
			/**
			 * Update the user PIN.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the PIN value.
			 * 
			 * input: see #changePin(byte[], short)
			 * output: none
			 * */
			case CLA_SEC_INS_CHANGE_PIN:
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				if (lc > PIN_DATA_MAX_SIZE)
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				initChangePin(buffer, lc);
				wrap(apdu, buffer, ZERO, ISO7816.SW_NO_ERROR);
				return;
			
			/**
			 * Return the number of free bytes in the persistent memory.
			 * If the number is greater than 0x7FFF, 0x7FFF is returned.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the returned data.
			 * 
			 * input: none
			 * output: available memory coded on two bytes.
			 * */
			case CLA_SEC_INS_AVAILABLE:
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				Util.setShort(buffer, ZERO, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
				wrap(apdu, buffer, (short) 2, ISO7816.SW_NO_ERROR);
				return;
				
			/**
			 * Create an new Group.
			 * This command may fail if no memory is available.
			 * 
			 * input: the Group name
			 * output: none
			 * */	
			case CLA_INS_CREATE_GROUP://No SM
				lc = apdu.setIncomingAndReceive();
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selection[GROUP_INDEX] = selectedGroup = new Group(buffer, ISO7816.OFFSET_CDATA, lc);
				groups.add(selectedGroup);
				return;
				
			/**
			 * Delete a Group.
			 * 
			 * input: the name of the Group to delete.
			 * output: none
			 * */
			case CLA_INS_DELETE_GROUP://No SM
				lc = apdu.setIncomingAndReceive();
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				groups.delete(buffer, ISO7816.OFFSET_CDATA, lc);
				return;
				
			/**
			 * Return the list of the name of the Groups.
			 * If the output buffer reaches 200 bytes, the list is paused and the 6310 SW is returned indicating that more data is available.
			 * Else the 9000 SW is returned indicating that all the Groups name have been returned.
			 * 
			 * p1: the index where starting to retrieve the Groups.
			 * input: none
			 * output: formatted as LVLVLV..., the names of the Groups.
			 * */
			case CLA_INS_LIST_GROUPS://No SM
				if (p1 >= groups.size() || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				lc = groups.list(buffer, p1);
				lc -= 2;//listIdentities() appends the SW at the end of the data
				apdu.setOutgoingAndSend(ZERO, lc);
				ISOException.throwIt(Util.getShort(buffer, lc));
				return;
				
			/**
			 * Select a Group, in order to execute future command on this Group.
			 * 
			 * input: the Group name
			 * output: none
			 * */
			case CLA_INS_SELECT_GROUP://No SM
				lc = apdu.setIncomingAndReceive();
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selection[GROUP_INDEX] = groups.get(buffer, ISO7816.OFFSET_CDATA, lc);
				return;
				
			/**
			 * Retrieve the number of Entries contained in the currently selected Group.
			 * 
			 * input: none
			 * output: the number of Entries, coded on two bytes.
			 * */
			case CLA_INS_GET_STATS://No SM
				Util.setShort(buffer, ZERO, selectedGroup.getNbEntries());
				apdu.setOutgoingAndSend(ZERO, (short) 2);
				return;
			
			/**
			 * Rename the currently selected Group.
			 * This command may fail if there is not enough memory to save the new name.
			 * 
			 * input: the new name
			 * output: none
			 * */
			case CLA_INS_RENAME_GROUP:
				lc = apdu.setIncomingAndReceive();
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selectedGroup.setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
				return;
				
			/**
			 * Move the currently selected Group in the list.
			 * 
			 * p1: 1 -> UP
			 *     2 -> DOWN
			 * input: none
			 * output: none
			 * */
			case CLA_INS_MOVE_GROUP:
				if (p2 != 0 || !groups.move(selectedGroup, p1))
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
				
				
			/**
			 * Create an Entry and add it in the currently selected Group.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the identifier.
			 * 
			 * p1: the number of data elements contained in the Entry.
			 * input: the identifier of the Entry
			 * output: none
			 * */
			case CLA_SEC_INS_ADD_ENTRY:
				if (p1 < 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selection[ENTRY_INDEX] = selectedEntry = selectedGroup.addEmptyEntry(p1);
				selectedEntry.setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
				wrapOk(apdu, buffer);
				return;
				
			/**
			 * Delete an Entry from the currently selected Group.
			 * Command executed under SM in order to ensure the confidentiality of the identifier.
			 * 
			 * input: the Entry identifier
			 * output: none
			 * */
			case CLA_SEC_INS_DELETE_ENTRY:
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selectedGroup.deleteEntry(buffer, ISO7816.OFFSET_CDATA, lc);
				wrapOk(apdu, buffer);
				return;
				
			/**
			 * Return the list of the Entries identifier of the currently selected Group.
			 * If the output buffer reaches 200 bytes, the list is paused and the 6310 SW is returned indicating that more data is available.
			 * Else the 9000 SW is returned indicating that all the Entries identifier have been returned.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the identifiers.
			 * 
			 * p1: the index where starting to retrieve the Entries.
			 * input: none
			 * output: formatted as LVLVLV..., the identifiers of the Entries.
			 * */
			case CLA_SEC_INS_LIST_ENTRIES:
				if (p1 >= selectedGroup.getNbEntries() || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				wrap(apdu, buffer, selectedGroup.listEntries(buffer, p1));
				return;
				
			/**
			 * Select an Entry within the currently selected Group, in order to execute future command on it.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the identifier.
			 * 
			 * input: the Entry identifier
			 * output: none
			 * */
			case CLA_SEC_INS_SELECT_ENTRY:
				if (p1 != 0 || p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				selection[ENTRY_INDEX] = selectedGroup.getEntry(buffer, ISO7816.OFFSET_CDATA, lc);
				wrapOk(apdu, buffer);
				return;
				
			/**
			 * Read data from the currently selected Entry.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the data.
			 * 
			 * p1: index of the data to read
			 * input: none
			 * output: the data
			 * */
			case CLA_SEC_INS_GET_DATA:
				wrap(apdu, buffer, selectedEntry.getData(p1, buffer, ZERO), ISO7816.SW_NO_ERROR);
				return;
				
			/**
			 * Write data to the currently selected Entry.
			 * 
			 * Command executed under SM in order to ensure the confidentiality of the data.
			 * 
			 * p1: index of the data to write
			 *     FF -> specific index value that updates the entry identifier
			 * input: the data
			 * output: none
			 * */
			case CLA_SEC_INS_SET_DATA:
				if (p1 == -1)
					selectedEntry.setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
				else
					selectedEntry.setData(p1, buffer, ISO7816.OFFSET_CDATA, lc);
				wrapOk(apdu, buffer);
				return;
				
			/**
			 * Read data from the currently selected Entry.
			 * 
			 * Command NOT executed under SM in order to improve performances.
			 * Data at index 0 cannot be retrieved through this command.
			 * 
			 * p1: index of the data to read
			 * input: none
			 * output: the data
			 * */
			case CLA_INS_GET_DATA://No SM
				apdu.setOutgoingAndSend(ZERO, selectedEntry.getData(p1, buffer, ZERO));
				return;
				
			/**
			 * Write data to the currently selected Entry.
			 * 
			 * Command NOT executed under SM in order to improve performances.
			 * Data at index 0 cannot be written through this command.
			 * 
			 * p1: index of the data to write
			 * input: the data
			 * output: none
			 * */
			case CLA_INS_SET_DATA://No SM
				lc = apdu.setIncomingAndReceive();
				selectedEntry.setData(p1, buffer, ISO7816.OFFSET_CDATA, lc);
				return;
				
			/**
			 * Move the currently selected Entry in the list or to another Group.
			 * 
			 * p1: 1 -> UP
			 *     2 -> DOWN
			 *     4 -> TO another Group
			 * input: if p1 is 1 or 2 -> none
			 *        if p1 is 4 -> the Group name to associate this Entry
			 * output: none
			 * */
			case CLA_INS_MOVE_ENTRY:
				if (p2 != 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				if (p1 == MOVE_UP || p1 == MOVE_DOWN) {
					if (!selectedGroup.entries.move(selectedEntry, p1))
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					return;
				}
				if (p1 == MOVE_TO) {
					lc = apdu.setIncomingAndReceive();
					
					//First, check that the given name corresponds to an existing Group
					tmp = (Group) groups.get(buffer, ISO7816.OFFSET_CDATA, lc);
					
					//Then, moving !
					selectedGroup.entries.remove(selectedEntry);
					tmp.entries.add(selectedEntry);
					
					//Invalidate Entry selection to avoid inconsistencies
					selection[ENTRY_INDEX] = null;
					return;
				}
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				return;
		}
		
		/* * * * * * * * * * * * * * 
		 *                         *
		 * End of main dispatcher  *
		 *                         *
		 * * * * * * * * * * * * * */
	}
	
	private void wrapOk(APDU apdu, byte[] buffer) {
		wrap(apdu, buffer, ZERO, ISO7816.SW_NO_ERROR);
	}
	private void wrap(APDU apdu, byte[] buffer, short len, short sw) {
		Util.setShort(buffer, len, sw);
		len += 2;
		
		apdu.setOutgoingAndSend(ZERO, scp.wrap(buffer, ZERO, len));
		ISOException.throwIt(sw);
	}
	private void wrap(APDU apdu, byte[] buffer, short len) {
		short sw = Util.getShort(buffer, (short) (len - 2));
		
		apdu.setOutgoingAndSend(ZERO, scp.wrap(buffer, ZERO, len));
		ISOException.throwIt(sw);
	}
	
	private void initChangePin(byte[] buffer, short lc) {
		if (transactionBuffer[TRNS_BUFF_STATUS_OFFSET] != STATUS_NO)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		JCSystem.beginTransaction();
		transactionBuffer[TRNS_BUFF_STATUS_OFFSET] = STATUS_ON;
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, transactionBuffer, TRNS_BUFF_DATA_OFFSET, lc);
		JCSystem.commitTransaction();
	}
	private void commitChangePin() {
		if (transactionBuffer[TRNS_BUFF_STATUS_OFFSET] != STATUS_ON)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		byte pinLen = transactionBuffer[TRNS_BUFF_PIN_LEN_OFFSET];
		OwnerPIN newPin = new OwnerPIN(transactionBuffer[TRNS_BUFF_PTL_OFFSET], pinLen);
		JCSystem.beginTransaction();
		scp.setKeys(transactionBuffer, TRNS_BUFF_KEYS_OFFSET);
		pin = newPin;
		pin.update(transactionBuffer, TRNS_BUFF_PIN_VAL_OFFSET, pinLen);
		abortChangePin();
		JCSystem.commitTransaction();
	}
	private void abortChangePin() {
		//No transaction
		transactionBuffer[TRNS_BUFF_STATUS_OFFSET] = STATUS_NO;
		random.generateData(transactionBuffer, TRNS_BUFF_KEYS_OFFSET, PIN_DATA_MAX_SIZE);
	}
}
