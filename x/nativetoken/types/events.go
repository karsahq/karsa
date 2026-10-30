package types

const (
	// EventTypeCreateToken is emitted when a native token is created.
	EventTypeCreateToken = "create_native_token"
	// EventTypeSetVerified is emitted when governance changes the curation flag.
	EventTypeSetVerified = "set_token_verified"

	// AttributeKeyDenom is the bank denom of the token.
	AttributeKeyDenom = "denom"
	// AttributeKeyAddress is the lowercase 0x address of the token.
	AttributeKeyAddress = "address"
	// AttributeKeyCreator is the creator address.
	AttributeKeyCreator = "creator"
	// AttributeKeyController is the controller contract address.
	AttributeKeyController = "controller"
	// AttributeKeyVerified is the new curation flag.
	AttributeKeyVerified = "verified"
)
