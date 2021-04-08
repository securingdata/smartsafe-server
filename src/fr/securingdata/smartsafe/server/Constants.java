package fr.securingdata.smartsafe.server;

public interface Constants {
	byte PIN_TRY_LIMIT_OFFSET = (byte) 37;
	byte PIN_SIZE_OFFSET      = (byte) 38;
	byte PIN_VALUE_OFFSET     = (byte) 39;

	byte CLA_SECURED      = (byte) 0x84;
	
	short SW_DATA_REMAINING = (short) 0x6310;
	
	short CLA_INS_INIT_UPDATE  = (short) 0x8050;
	short CLA_INS_EXT_AUTH     = (short) 0x8482;
	
	short CLA_SEC_INS_AUTHENTICATE = (short) 0x8401;
	short CLA_INS_INIT_PIN         = (short) 0x0002;//Executed before authentication, no SM
	short CLA_SEC_INS_CHANGE_PIN   = (short) 0x8402;
	short CLA_SEC_INS_AVAILABLE    = (short) 0x8403;
	short CLA_INS_GET_VERSION      = (short) 0x0004;//Executed at any time, no SM
	
	/* Group related command do not handle sensitive data, no SM */
	short CLA_INS_CREATE_GROUP = (short) 0x0011;
	short CLA_INS_DELETE_GROUP = (short) 0x0012;
	short CLA_INS_LIST_GROUPS  = (short) 0x0013;
	short CLA_INS_SELECT_GROUP = (short) 0x0014;
	short CLA_INS_GET_STATS    = (short) 0x0015;
	short CLA_INS_RENAME_GROUP = (short) 0x0016;
	short CLA_INS_MOVE_GROUP   = (short) 0x0017;
	
	/* Entry related commands are almost all under SM */
	short CLA_SEC_INS_ADD_ENTRY    = (short) 0x8421;
	short CLA_SEC_INS_DELETE_ENTRY = (short) 0x8422;
	short CLA_SEC_INS_LIST_ENTRIES = (short) 0x8423;
	short CLA_SEC_INS_SELECT_ENTRY = (short) 0x8424;
	short CLA_SEC_INS_GET_DATA     = (short) 0x8425;
	short CLA_SEC_INS_SET_DATA     = (short) 0x8426;
	short CLA_INS_GET_DATA         = (short) 0x0025;//For not sensitive data only
	short CLA_INS_SET_DATA         = (short) 0x0026;//For not sensitive data only
	short CLA_INS_MOVE_ENTRY       = (short) 0x0027;//This command does not transport sensitive data
	
	byte MOVE_UP   = (byte) 0x01;
	byte MOVE_DOWN = (byte) 0x02;
	byte MOVE_TO   = (byte) 0x04;
	
	byte ZERO = (byte) 0x00;
	
	byte GROUP_INDEX = (byte) 0;
	byte ENTRY_INDEX = (byte) 1;
}
