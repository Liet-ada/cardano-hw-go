// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

// The command tree of cardano-hw-cli, option by option.

const derivationTypeHelp = "Derivation type - currently applies only to Trezor. Options: LEDGER, ICARUS or ICARUS_TREZOR (default)."

var derivationTypeOpt = option{name: "--derivation-type", dest: "derivationType", metavar: "DERIVATIONTYPE", help: derivationTypeHelp, conv: convDerivationType}

var allowUnrestrictedOpt = option{name: "--allow-unrestricted-mode", dest: "allowUnrestrictedMode", flag: true,
	help: "Permit hw-cli to use unrestricted signing mode for transactions that require it (Ledger app v8 or newer with expert mode enabled on the device), and to silently ignore a fixed set of unfixable CIP-21 validation issues (pool-registration combination rules and certain voting-procedure rules). Default: false — without this flag, hw-cli refuses to sign such transactions. In unrestricted mode the device shows all transaction elements for the expert user to review."}

var networkOpts = []option{
	{name: "--mainnet", dest: "network", metavar: "NETWORK", optional: true, constant: "mainnet", help: "NETWORK."},
	{name: "--testnet-magic", dest: "network", metavar: "NETWORK", optional: true, help: "Protocol magic number."},
}

func txFileOpt() option {
	return option{name: "--tx-file", dest: "txFileData", metavar: "TXFILEDATA", required: true,
		help: "Input filepath of the tx. Use --cddl-format when building transactions with cardano-cli.", conv: convTxFile}
}

func rootCommand() *command {
	keyGen := []option{
		{name: "--path", dest: "paths", metavar: "PATHS", required: true, repeat: true, help: "Derivation path to the key to sign with.", conv: convPath},
		{name: "--hw-signing-file", dest: "hwSigningFiles", metavar: "HWSIGNINGFILES", required: true, repeat: true, help: "Output filepath of the verification key."},
		{name: "--verification-key-file", dest: "verificationKeyFiles", metavar: "VERIFICATIONKEYFILES", required: true, repeat: true, help: "Output filepath of the hardware wallet signing file."},
		derivationTypeOpt,
	}
	witness := append(append([]option{}, networkOpts...),
		txFileOpt(),
		option{name: "--hw-signing-file", dest: "hwSigningFileData", metavar: "HWSIGNINGFILEDATA", required: true, repeat: true, help: "Input filepath of the hardware wallet signing file.", conv: convSigningFile},
		option{name: "--change-output-key-file", dest: "changeOutputKeyFileData", metavar: "CHANGEOUTPUTKEYFILEDATA", repeat: true, help: "Input filepath of change output file.", conv: convSigningFile},
		allowUnrestrictedOpt,
		derivationTypeOpt,
		option{name: "--out-file", dest: "outFiles", metavar: "OUTFILES", required: true, repeat: true, help: "Output filepath."},
	)
	return &command{
		help: "Command line tool for ledger/trezor/keystone transaction signing",
		subs: []*command{
			{name: "version"},
			{name: "device", subs: []*command{{name: "version"}}},
			{name: "key", subs: []*command{{name: "verification-key", opts: []option{
				{name: "--hw-signing-file", dest: "hwSigningFileData", metavar: "HWSIGNINGFILEDATA", required: true, help: "Input filepath of the hardware wallet signing file.", conv: convSigningFile},
				{name: "--verification-key-file", dest: "verificationKeyFile", metavar: "VERIFICATIONKEYFILE", required: true, help: "Output filepath of the verification key."},
			}}}},
			{name: "address", subs: []*command{
				{name: "key-gen", opts: keyGen},
				{name: "show", groups: []group{
					{options: []option{
						{name: "--payment-path", dest: "paymentPath", metavar: "PAYMENTPATH", help: "Payment derivation path. Either this or payment script hash has to be specified.", conv: convPath},
						{name: "--payment-script-hash", dest: "paymentScriptHash", metavar: "PAYMENTSCRIPTHASH", help: "Payment derivation script hash in hex format.", conv: convScriptHash},
					}},
					{options: []option{
						{name: "--staking-path", dest: "stakingPath", metavar: "STAKINGPATH", help: "Stake derivation path. Either this or staking script hash has to be specified.", conv: convPath},
						{name: "--staking-script-hash", dest: "stakingScriptHash", metavar: "STAKINGSCRIPTHASH", help: "Stake derivation script hash in hex format", conv: convScriptHash},
					}},
				}, opts: []option{
					{name: "--address-file", dest: "address", metavar: "ADDRESS", required: true, help: "Input filepath of the address.", conv: convAddressFile},
					derivationTypeOpt,
				}},
			}},
			{name: "transaction", subs: []*command{
				{name: "policyid", opts: []option{
					{name: "--script-file", dest: "nativeScript", metavar: "NATIVESCRIPT", required: true, help: "Filepath of the script.", conv: convNativeScript},
					{name: "--hw-signing-file", dest: "hwSigningFileData", metavar: "HWSIGNINGFILEDATA", repeat: true, help: "Input filepath of the hardware wallet signing file.", conv: convSigningFile},
					derivationTypeOpt,
				}},
				{name: "witness", opts: witness},
				{name: "validate", opts: []option{txFileOpt(), allowUnrestrictedOpt}},
				{name: "transform", opts: []option{
					txFileOpt(),
					{name: "--out-file", dest: "outFile", metavar: "OUTFILE", required: true, help: "Output filepath."},
					allowUnrestrictedOpt,
					{name: "--protocol-params-file", dest: "protocolParamsData", metavar: "PROTOCOLPARAMSDATA", help: "Path to a protocol parameters JSON file (from cardano-cli query protocol-parameters). Required for transactions with Plutus scripts.", conv: convProtocolParams},
					{name: "--used-cost-model-languages", dest: "usedCostModelLanguages", metavar: "USEDCOSTMODELLANGUAGES", repeat: true, help: "Plutus language versions used in the transaction (e.g. PlutusV1 PlutusV2 PlutusV3). Required for reference-script-only transactions where language versions cannot be inferred from the witness set."},
				}},
			}},
			{name: "node", subs: []*command{
				{name: "key-gen", opts: []option{
					{name: "--path", dest: "paths", metavar: "PATHS", required: true, repeat: true, help: "Derivation path to the key to sign with.", conv: convPath},
					{name: "--hw-signing-file", dest: "hwSigningFiles", metavar: "HWSIGNINGFILES", required: true, repeat: true, help: "Output filepath of the verification key."},
					{name: "--cold-verification-key-file", dest: "verificationKeyFiles", metavar: "VERIFICATIONKEYFILES", required: true, repeat: true, help: "Output filepath of the hardware wallet signing file."},
					{name: "--operational-certificate-issue-counter-file", dest: "issueCounterFiles", metavar: "ISSUECOUNTERFILES", required: true, repeat: true, help: "Output filepath of the issue counter file."},
				}},
				{name: "issue-op-cert", opts: []option{
					{name: "--kes-verification-key-file", dest: "kesVKey", metavar: "KESVKEY", required: true, help: "Input filepath of the KES vkey.", conv: convKESVKey},
					{name: "--kes-period", dest: "kesPeriod", metavar: "KESPERIOD", required: true, help: "KES period.", conv: convBigInt},
					{name: "--operational-certificate-issue-counter-file", dest: "issueCounterFile", metavar: "ISSUECOUNTERFILE", help: "Input filepath of the issue counter file."},
					{name: "--hw-signing-file", dest: "hwSigningFileData", metavar: "HWSIGNINGFILEDATA", required: true, repeat: true, help: "Input filepath of the hardware wallet signing file."},
					{name: "--out-file", dest: "outFile", metavar: "OUTFILE", required: true, help: "Output filepath."},
				}},
			}},
			{name: "vote", subs: []*command{{name: "registration-metadata", opts: append(append([]option{}, networkOpts...),
				option{name: "--vote-public-key-jcli", dest: "votePublicKeys", metavar: "VOTEPUBLICKEYS", repeat: true, help: "Input filepath to vote public key in ed25519extended format (one or more keys can be provided).", conv: convVoteKeyJcli},
				option{name: "--vote-public-key-string", dest: "votePublicKeys", metavar: "VOTEPUBLICKEYS", repeat: true, help: "Bech32-encoded vote public key (one or more keys can be provided).", conv: convVoteKeyString},
				option{name: "--vote-public-key-hwsfile", dest: "votePublicKeys", metavar: "VOTEPUBLICKEYS", repeat: true, help: "Input filepath to vote public key in hw-signing-file format (one or more keys can be provided).", conv: convVoteKeyHwsfile},
				option{name: "--vote-public-key-file", dest: "votePublicKeys", metavar: "VOTEPUBLICKEYS", repeat: true, help: "Input filepath to vote public key in cardano-cli file format (one or more keys can be provided).", conv: convVoteKeyFile},
				option{name: "--vote-weight", dest: "voteWeights", metavar: "VOTEWEIGHTS", repeat: true, help: "Weight assigned to the respective vote public key.", conv: convBigInt},
				option{name: "--stake-signing-key-hwsfile", dest: "hwStakeSigningFileData", metavar: "HWSTAKESIGNINGFILEDATA", required: true, help: "Input filepath of the hardware wallet stake signing file, which will be used to to sign the registration.", conv: convSigningFile},
				option{name: "--payment-address", dest: "paymentAddress", metavar: "PAYMENTADDRESS", required: true, help: "Address to receive voting rewards (in bech32)."},
				option{name: "--nonce", dest: "nonce", metavar: "NONCE", required: true, help: "Current slot number.", conv: convBigInt},
				option{name: "--voting-purpose", dest: "votingPurpose", metavar: "VOTINGPURPOSE", help: "Voting purpose.", conv: convBigInt},
				option{name: "--payment-address-signing-key-hwsfile", dest: "paymentAddressSigningKeyData", metavar: "PAYMENTADDRESSSIGNINGKEYDATA", repeat: true, help: "Input filepath of the payment address hardware wallet signing file.", conv: convSigningFile},
				option{name: "--metadata-cbor-out-file", dest: "outFile", metavar: "OUTFILE", required: true, help: "Output metadata cbor filepath."},
				derivationTypeOpt,
			)}}},
			{name: "message", subs: []*command{{name: "sign", groups: []group{{required: true, options: []option{
				{name: "--message", dest: "message", metavar: "MESSAGE_ASCII", help: "Message in ASCII.", conv: convMessage},
				{name: "--message-hex", dest: "messageHex", metavar: "MESSAGE_HEX", help: "Message in hex."},
			}}}, opts: []option{
				{name: "--signing-path-hwsfile", dest: "hwSigningFileData", metavar: "HWSIGNINGFILEDATA", required: true, help: "Input filepath of the hardware wallet signing file describing the key to be used to sign the message.", conv: convSigningFile},
				{name: "--hashed", dest: "hashPayload", flag: true, help: "If present, the message will be hashed; otherwise it will not be hashed."},
				{name: "--prefer-hex", dest: "preferHexDisplay", flag: true, help: "If present, the message will be shown in hex even if it is valid ASCII."},
				{name: "--address", dest: "address", metavar: "ADDRESS", help: "Address for the COSE header (if not given, signing key hash is used)."},
				{name: "--address-hwsfile", dest: "addressHwSigningFileData", metavar: "ADDRESSHWSIGNINGFILEDATA", repeat: true, help: "Input filepath of an address hardware wallet signing file.", conv: convSigningFile},
				{name: "--out-file", dest: "outFile", metavar: "OUTFILE", required: true, help: "Output filepath."},
				derivationTypeOpt,
			}}}},
		},
	}
}
