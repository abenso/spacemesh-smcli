package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/spacemeshos/economics/constants"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spacemeshos/go-spacemesh/config"
	"github.com/spacemeshos/go-spacemesh/config/presets"
	genvm "github.com/spacemeshos/go-spacemesh/genvm"
	"github.com/spacemeshos/go-spacemesh/genvm/core"
	"github.com/spacemeshos/go-spacemesh/genvm/sdk"
	"github.com/spacemeshos/go-spacemesh/log"

	sdkMultisig "github.com/spacemeshos/go-spacemesh/genvm/sdk/multisig"
	sdkVesting "github.com/spacemeshos/go-spacemesh/genvm/sdk/vesting"
	sdkWallet "github.com/spacemeshos/go-spacemesh/genvm/sdk/wallet"
	templateMultisig "github.com/spacemeshos/go-spacemesh/genvm/templates/multisig"
	templateVault "github.com/spacemeshos/go-spacemesh/genvm/templates/vault"
	templateVesting "github.com/spacemeshos/go-spacemesh/genvm/templates/vesting"
	"github.com/spacemeshos/go-spacemesh/genvm/templates/wallet"
	templateWallet "github.com/spacemeshos/go-spacemesh/genvm/templates/wallet"
	"github.com/spacemeshos/go-spacemesh/signing"
	"github.com/spacemeshos/go-spacemesh/sql"
	"go.uber.org/zap"
)

type TypeAccount string

const (
	Wallet   TypeAccount = "Wallet"
	Multisig TypeAccount = "Multisig"
	Vault    TypeAccount = "Vault"
	Vesting  TypeAccount = "Vesting"
)

type TypeTx string

const (
	Spawn     TypeTx = "spawn"
	SelfSpawn TypeTx = "self_spawn"
	Spend     TypeTx = "spend"
	Drain     TypeTx = "drain"
	// applied to state but not output in tests
	Ignore TypeTx = "ignore"
)

type TestVector struct {
	// always print these
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Blob    string `json:"blob"`
	Mainnet bool   `json:"mainnet"`

	// we custom print these depending on account and tx type
	m, n, part, method uint8
	destination,
	vault,
	principal,
	template,
	hrp string
	amount,
	gasMax,
	gasPrice,
	maxSpend,
	nonce uint64
	typeAccount                      TypeAccount
	typeTx                           TypeTx
	multisigPublicKeys               []core.PublicKey
	owner                            string
	totalAmount, initialUnlockAmount uint64
	vestingStart, vestingEnd         uint32
	genesisID                        []byte
}

// "6 | TotalAmount : 100",
// "7 | InitialUnlockAmount : 10",
// "8 | VestingStart : 1",
// "9 | VestingStart : 10"

func formatAmount(amount uint64) string {
	// Convert the amount to a string
	amountStr := fmt.Sprintf("%d", amount)

	// If the length of the string is less than 9, pad with leading zeros
	if len(amountStr) <= 9 {
		amountStr = strings.Repeat("0", 9-len(amountStr)) + amountStr
	}

	// Insert the decimal point 9 places from the right
	intPart := amountStr[:len(amountStr)-9]
	fracPart := amountStr[len(amountStr)-9:]

	// Remove trailing zeros in fractional part
	fracPart = strings.TrimRight(fracPart, "0")

	// If the fractional part is empty, set it to "0"
	if fracPart == "" {
		fracPart = "0"
	}

	// If the integer part is empty, set it to "0"
	if intPart == "" {
		intPart = "0"
	}

	return fmt.Sprintf("%s.%s", intPart, fracPart)
}

func (tv TestVector) MarshalJSON() ([]byte, error) {
	type Alias TestVector
	index := 0
	output := []string{}
	addString := func(s string) {
		output = append(output, fmt.Sprintf("%d | %s", index, s))
		index++
	}

	addStringNoInc := func(s string) {
		output = append(output, fmt.Sprintf("%d | %s", index, s))
	}

	// add account-based details
	aux := string(tv.typeTx)
	aux = strings.TrimPrefix(aux, "self_")

	switch tv.typeAccount {
	case Vesting:
		fallthrough
	default:
		if aux == "spend" {
			aux = strings.ToUpper(aux[0:1]) + aux[1:]
			addString(fmt.Sprintf("Tx type : %s", aux))
		} else {
			addString(fmt.Sprintf("Tx type : %s %s", tv.typeAccount, aux))
		}
	}
	offset := 10
	if !tv.Mainnet {
		offset = 13
	}
	addStringNoInc(fmt.Sprintf("Principal [1/2] : %s", tv.principal[:38]))
	addString(fmt.Sprintf("Principal [2/2] : %s", tv.principal[38:38+offset]))
	//addString(fmt.Sprintf("Max Gas : %d", tv.gasMax))

	// add tx-based details
	switch tv.typeTx {
	// nothing to add for spawn
	case Drain:
		addStringNoInc(fmt.Sprintf("Vault [1/2] : %s", tv.vault[:38]))
		addString(fmt.Sprintf("Vault [2/2] : %s", tv.vault[38:38+offset]))
		fallthrough
	case Spend:
		addStringNoInc(fmt.Sprintf("Destination [1/2] : %s", tv.destination[:38]))
		addString(fmt.Sprintf("Destination [2/2] : %s", tv.destination[38:38+offset]))
		addString(fmt.Sprintf("Amount : SMH %s", formatAmount(tv.amount)))
	}
	addString(fmt.Sprintf("Gas price : SMIDGE %d", tv.gasPrice))
	if (tv.typeAccount == Vault) && (tv.typeTx == Spawn || tv.typeTx == SelfSpawn) {
		addStringNoInc(fmt.Sprintf("Owner [1/2] : %s", tv.owner[:38]))
		addString(fmt.Sprintf("Owner [2/2] : %s", tv.owner[38:38+offset]))

		addString(fmt.Sprintf("TotalAmount : SMH %s", formatAmount(tv.totalAmount)))
		addString(fmt.Sprintf("InitialUnlockAmount : SMH %s", formatAmount(tv.initialUnlockAmount)))
		addString(fmt.Sprintf("VestingStart : %d", tv.vestingStart))
		addString(fmt.Sprintf("VestingEnd : %d", tv.vestingEnd))
	}

	if (tv.typeAccount == Multisig || tv.typeAccount == Vesting) && (tv.typeTx == Spawn || tv.typeTx == SelfSpawn) {
		addString(fmt.Sprintf("Participants : %d", tv.n))
		addString(fmt.Sprintf("Validators : %d", tv.m))
		for i, pubkey := range tv.multisigPublicKeys {
			types.SetNetworkHRP("sm")
			if !tv.Mainnet {
				types.SetNetworkHRP("stest")
			}

			hexString := hex.EncodeToString(pubkey.Bytes())
			addStringNoInc(fmt.Sprintf("Pubkey %d [1/2] : %s", i, hexString[:38]))
			addString(fmt.Sprintf("Pubkey %d [2/2] : %s", i, hexString[38:64]))

			walletArgs := &wallet.SpawnArguments{PublicKey: pubkey}
			walletAddress := core.ComputePrincipal(wallet.TemplateAddress, walletArgs)
			pubString := walletAddress.String()
			addStringNoInc(fmt.Sprintf("Address %d [1/2] : %s", i, pubString[:38]))
			addString(fmt.Sprintf("Address %d [2/2] : %s", i, pubString[38:38+offset]))

		}
	}

	// expert mode: add info on chain ID and nonce
	outputExpert := make([]string, len(output))
	copy(outputExpert, output)
	addStringExpert := func(s string) {
		outputExpert = append(outputExpert, fmt.Sprintf("%d | %s", index, s))
		index++
	}

	addStringExpertNoInc := func(s string) {
		outputExpert = append(outputExpert, fmt.Sprintf("%d | %s", index, s))
	}

	//addStringExpert(fmt.Sprintf("Chain : %s", tv.hrp))
	if tv.typeTx == Spawn || tv.typeTx == SelfSpawn {
		addStringExpertNoInc(fmt.Sprintf("Template [1/2] : %s", tv.template[:38]))
		addStringExpert(fmt.Sprintf("Template [2/2] : %s", tv.template[38:38+offset]))
	}
	addStringExpert(fmt.Sprintf("Nonce : %d", tv.nonce))
	addStringExpert(fmt.Sprintf("Method : %d", tv.method))

	genesisString := hex.EncodeToString(tv.genesisID)
	addStringExpertNoInc(fmt.Sprintf("Genesis Id [1/2] : %s", genesisString[:38]))
	addStringExpert(fmt.Sprintf("Genesis Id [2/2] : %s", genesisString[38:40]))

	return json.Marshal(struct {
		Alias
		Output       []string `json:"output"`
		OutputExpert []string `json:"output_expert"`
	}{
		Alias:        Alias(tv),
		Output:       output,
		OutputExpert: outputExpert,
	})
}

func init() {
	// Set log level based on an environment variable
	level := zap.InfoLevel
	if os.Getenv("DEBUG") != "" {
		level = zap.DebugLevel
	}
	log.SetLogger(log.NewWithLevel("testvectors", zap.NewAtomicLevelAt(level)))
}

// generate a random address for testing
func generateAddress() types.Address {
	pub, _ := getKey()
	return types.GenerateAddress(pub)
}

func applyTx(tx []byte, vm *genvm.VM) {
	validator := vm.Validation(types.NewRawTx(tx))
	header, err := validator.Parse()
	if err != nil {
		log.Fatal("Error parsing transaction to apply: %v", err)
	}
	coreTx := types.Transaction{
		TxHeader: header,
		RawTx:    types.NewRawTx(tx),
	}
	skipped, results, err := vm.Apply(genvm.ApplyContext{Layer: types.FirstEffectiveGenesis()}, []types.Transaction{coreTx}, []types.CoinbaseReward{})
	if len(skipped) != 0 {
		log.Fatal("Error applying transaction: transaction skipped")
	} else if len(results) != 1 {
		log.Fatal("Error applying transaction: unexpected number of results (tx failed)")
	} else if results[0].Status != types.TransactionSuccess {
		log.Fatal("Error applying transaction: %v", results[0].Status)
	} else if err != nil {
		log.Fatal("Error applying transaction: %v", err)
	}
	log.Debug("got result: %v", results[0].TransactionResult)
}

// m, n only used for multisig; ignored for single sig wallet
func txToTestVector(
	tx []byte,
	vm *genvm.VM,
	index int,
	amount uint64,
	accountType TypeAccount,
	txType TypeTx,
	destination, hrp, vault string,
	m, n uint8,
	validity bool,
	part uint8,
	multisigPublicKeys []core.PublicKey,
	owner string,
	totalAmount, initialUnlockAmount uint64,
	vestingStart, vestingEnd uint32,
	genesisID types.Hash20,
) TestVector {
	validator := vm.Validation(types.NewRawTx(tx))
	header, err := validator.Parse()
	if err != nil {
		log.Fatal("Error parsing transaction idx %d: %v", index, err)
	}

	// we should be able to validate all txs EXCEPT partially aggregated multisig txs,
	// which are not valid as standalone txs
	if !validator.Verify() {
		if validity {
			log.Fatal("Error validating supposedly valid transaction idx %d", index)
		}
		log.Debug("Expected error parsing partially aggregated transaction idx %d, ignoring", index)
	}

	// format the vector name
	var name string

	// single sig wallet txs are simple
	if accountType == Wallet {
		name = fmt.Sprintf("%s_%s_%s", hrp, accountType, txType)
	} else {
		// for multisig, we need to include more information
		name = fmt.Sprintf("%s_%s_%d_%d_%s", hrp, accountType, m, n, txType)
	}

	mainnet := true
	if strings.HasPrefix(header.Principal.String(), "stest") {
		mainnet = false
	}

	var blob []byte
	if accountType == Wallet {
		blob = tx[:len(tx)-64]
	} else if accountType == Multisig || accountType == Vesting || accountType == Vault {
		blob = tx[:len(tx)-65]
	} else {
		blob = tx
		//panic("implement this")
	}
	full := make([]byte, 0, len(genesisID)+len(tx))
	full = append(full, genesisID[:]...)
	full = append(full, blob...)

	return TestVector{
		Index:   index,
		Name:    name,
		Blob:    fmt.Sprintf("%X", full),
		Mainnet: mainnet,

		// note: not all fields used in all tx types.
		// will be decoded in output.
		hrp:                 hrp,
		m:                   m,
		n:                   n,
		part:                part,
		method:              header.Method,
		destination:         destination,
		amount:              amount,
		gasMax:              header.MaxGas,
		gasPrice:            header.GasPrice,
		maxSpend:            header.MaxSpend,
		nonce:               header.Nonce,
		principal:           header.Principal.String(),
		template:            header.TemplateAddress.String(),
		typeAccount:         accountType,
		typeTx:              txType,
		vault:               vault,
		multisigPublicKeys:  multisigPublicKeys,
		owner:               owner,
		totalAmount:         totalAmount,
		initialUnlockAmount: initialUnlockAmount,
		vestingStart:        vestingStart,
		vestingEnd:          vestingEnd,
		genesisID:           genesisID[:],
	}
}

type TxPair struct {
	txtype TypeTx
	tx     []byte

	// multisig txs come in parts, e.g., for a 2-of-2 tx we have two parts
	// we don't use this for single sig wallet txs
	part uint8

	// whether this tx is valid as a standalone tx
	// partially-aggregated multisig txs are not standalone valid so we don't attempt to validate them!
	valid bool

	// there's no way to extract this from the tx data so we need to store it separately here
	// if we want to display it in the vector
	// used for vesting drain tx
	vault string

	genesisID types.Hash20
}

// maximum "n" value for multisig
const MaxKeys = 10

func processTxList(
	txList []TxPair,
	hrp string,
	accountType TypeAccount,
	index int,
	vm *genvm.VM,
	destination types.Address,
	m, n uint8,
	multisigPublicKeys []core.PublicKey,
	amount uint64,
	vaultArgs templateVault.SpawnArguments,

) []TestVector {
	testVectors := []TestVector{}
	for _, txPair := range txList {
		if txPair.txtype == Ignore {
			log.Debug("Applying tx ignored for test vectors for %s %s", hrp, accountType)
			applyTx(txPair.tx, vm)
			continue
		}
		log.Debug("[%d] Generating test vector for %s %s %s %d of %d", index, hrp, accountType, txPair.txtype, m, n)
		testVector := txToTestVector(
			txPair.tx,
			vm,
			index,
			amount,
			accountType,
			txPair.txtype,
			destination.String(),
			hrp,
			txPair.vault,
			m,
			n,
			txPair.valid,
			txPair.part,
			multisigPublicKeys,
			vaultArgs.Owner.String(),
			vaultArgs.TotalAmount,
			vaultArgs.InitialUnlockAmount,
			uint32(vaultArgs.VestingStart),
			uint32(vaultArgs.VestingEnd),
			txPair.genesisID,
		)
		testVectors = append(testVectors, testVector)
		index++
	}
	return testVectors
}

func handleMultisig(
	vm *genvm.VM,
	opts []sdk.Opt,
	destination types.Address,
	hrp string,
	templateAddress types.Address,
	principalMultisig types.Address,
	spawnArgsMultisig *templateMultisig.SpawnArguments,
	pubkeysSigning []signing.PublicKey,
	pubkeysCore []core.PublicKey,
	pubkeysEd []ed25519.PublicKey,
	privkeys []ed25519.PrivateKey,
	m, n uint8,
	amount uint64,
	genesisID types.Hash20,
) []TxPair {
	// we also need the separate principal for each signer
	principalSigners := make([]types.Address, m)
	for i := uint8(0); i < m; i++ {
		// assume signers are simple wallet holders
		principalSigners[i] = core.ComputePrincipal(templateWallet.TemplateAddress, &templateWallet.SpawnArguments{PublicKey: pubkeysCore[i]})
	}

	log.Debug("m-of-n: %d of %d, principal: %s", m, n, principalMultisig.String())

	// fund the principal account (to allow verification later)
	// also fund the first signer so it can spawn itself
	vm.ApplyGenesis([]types.Account{
		{
			Address: principalMultisig,
			Balance: constants.OneSmesh,
		},
		// {
		// 	Address: principalSigners[0],
		// 	Balance: constants.OneSmesh,
		// },
	})

	txList := []TxPair{}

	// multisig operations require m signers per operation
	// spawn principal can be signer or multisig itself
	// self spawn principal is the multisig itself
	// spend principal can be either

	// we model signer as principal since this use case is more realistic, i.e., one of the signers
	// pays the gas for the spawn
	// but the signer account also needs to be spawned first
	// txList = append(
	// 	txList,
	// 	TxPair{
	// 		txtype: Ignore,
	// 		tx:     sdkWallet.SelfSpawn(privkeys[0], 0, opts...),
	// 	},
	// )

	// TODO: investigate why this doesn't work, i.e., why the first signer can't be used
	// as the spawn principal (pay the fees for the spawn)
	// spawnAgg := sdkMultisig.Spawn(0, privkeys[0], principalSigners[0], templateMultisig.TemplateAddress, spawnArgsMultisig, 0, opts...)
	spawnAgg := sdkMultisig.Spawn(0, privkeys[0], principalMultisig, templateAddress, spawnArgsMultisig, 0, opts...)
	selfSpawnAgg := sdkMultisig.SelfSpawn(0, privkeys[0], templateAddress, m, pubkeysEd[:n], 0, opts...)
	spendAgg := sdkMultisig.Spend(0, privkeys[0], principalMultisig, destination, amount, 0, opts...)

	// add an individual test vector for each signing operation
	// one list per tx type so we can assemble the final list in order
	// start with the first operation
	// three m-length lists plus one additional, final, aggregated self-spawn tx
	txListSpawn := make([]TxPair, 1)
	txListSelfSpawn := make([]TxPair, 1)
	txListSpend := make([]TxPair, 1)

	// multisig txs are valid as standalone only if idx==m-1, i.e., it's the final part
	txListSpawn[0] = TxPair{txtype: Spawn, tx: spawnAgg.Raw(), valid: m == 1, part: 0, genesisID: genesisID}
	txListSelfSpawn[0] = TxPair{txtype: SelfSpawn, tx: selfSpawnAgg.Raw(), valid: m == 1, part: 0, genesisID: genesisID}
	txListSpend[0] = TxPair{txtype: Spend, tx: spendAgg.Raw(), valid: m == 1, part: 0, genesisID: genesisID}

	// now add a test vector for each additional required signature
	// note: this assumes signer n has the signed n-1 tx
	// for signerIdx := uint8(1); signerIdx < m; signerIdx++ {
	// 	spawnAgg.Add(*sdkMultisig.Spawn(signerIdx, privkeys[signerIdx], principalMultisig, templateAddress, spawnArgsMultisig, 0, opts...).Part(signerIdx))
	// 	selfSpawnAgg.Add(*sdkMultisig.SelfSpawn(signerIdx, privkeys[signerIdx], templateAddress, m, pubkeysEd[:n], 0, opts...).Part(signerIdx))
	// 	spendAgg.Add(*sdkMultisig.Spend(signerIdx, privkeys[signerIdx], principalMultisig, destination, Amount, 0, opts...).Part(signerIdx))

	// 	// only the final, fully aggregated tx is valid
	// 	txListSpawn[signerIdx] = TxPair{txtype: Spawn, tx: spawnAgg.Raw(), valid: signerIdx == m-1, part: signerIdx}
	// 	txListSelfSpawn[signerIdx] = TxPair{txtype: SelfSpawn, tx: selfSpawnAgg.Raw(), valid: signerIdx == m-1, part: signerIdx}
	// 	txListSpend[signerIdx] = TxPair{txtype: Spend, tx: spendAgg.Raw(), valid: signerIdx == m-1, part: signerIdx}
	// }

	// assemble the final list of txs in order: spawn, self-spawn, final aggregated self-spawn to apply, spend
	txList = append(txList, txListSpawn...)
	txList = append(txList, txListSelfSpawn...)
	txList = append(txList, TxPair{txtype: Ignore, tx: selfSpawnAgg.Raw()})
	txList = append(txList, txListSpend...)

	return txList
}

const Amount = uint64(constants.OneSmesh)

func generateKeys(n int) ([]signing.PublicKey, []core.PublicKey, []ed25519.PublicKey, []ed25519.PrivateKey) {
	// generate the required set of keypairs

	// frustratingly, we need the same list of pubkeys in multiple formats
	// https://github.com/spacemeshos/go-spacemesh/issues/6061
	pubkeysSigning := make([]signing.PublicKey, n)
	pubkeysCore := make([]core.PublicKey, n)
	pubkeysEd := make([]ed25519.PublicKey, n)
	privkeys := make([]signing.PrivateKey, n)
	for i := 0; i < n; i++ {
		pubkeysEd[i], privkeys[i] = getKey()
		pubkeysCore[i] = types.BytesToHash(pubkeysEd[i])
		pubkeysSigning[i] = signing.PublicKey{PublicKey: pubkeysEd[i]}
	}
	return pubkeysSigning, pubkeysCore, pubkeysEd, privkeys
}

func generateTestVectors() []TestVector {
	// Set log level based on an environment variable
	level := zap.WarnLevel
	if os.Getenv("DEBUG") != "" {
		level = zap.DebugLevel
	}

	// read network configs - needed for genesisID
	var configMainnet, configTestnet config.GenesisConfig
	configMainnet = config.MainnetConfig().Genesis

	// this isn't very important but we should set it to something reasonable
	types.SetLayersPerEpoch(config.MainnetConfig().LayersPerEpoch)

	if testnet, err := presets.Get("testnet"); err != nil {
		log.Fatal("Error getting testnet config: %v", err)
	} else {
		configTestnet = testnet.Genesis
	}
	// not sure how to get hrp programmatically from config so we just hardcode it
	networks := map[string]config.GenesisConfig{
		"sm":    configMainnet,
		"stest": configTestnet,
	}

	testVectors := []TestVector{}
	// just use a single, random destination address
	// note: destination is not used in all tx types
	destination := generateAddress()
	for hrp, netconf := range networks {
		log.Debug("NETWORK: %s", hrp)
		// hrp is used in address generation
		types.SetNetworkHRP(hrp)

		// initialization
		genesisID := netconf.GenesisID()
		fmt.Println("genesisID", genesisID.String())

		// we need a VM object for validation and gas cost computation
		vm := genvm.New(
			sql.InMemory(),
			genvm.WithConfig(genvm.Config{GasLimit: math.MaxUint64, GenesisID: genesisID}),
			genvm.WithLogger(log.NewWithLevel("genvm", zap.NewAtomicLevelAt(level))),
		)

		// SIMPLE WALLET (SINGLE SIG)
		log.Debug("TEMPLATE: WALLET")

		// generate a single key
		_, pubkeysCore, _, privkeys := generateKeys(1)

		spawnArgsWallet := &templateWallet.SpawnArguments{
			PublicKey: pubkeysCore[0],
		}
		principal := core.ComputePrincipal(templateWallet.TemplateAddress, spawnArgsWallet)

		// our random account needs a balance so it can be spawned
		// this is not strictly necessary for the test vectors but it allows us to perform validation
		vm.ApplyGenesis([]types.Account{{
			Address: principal,
			Balance: constants.OneSmesh,
		}})

		// need a list, not a map, since order matters here
		// (self-spawn must come before spend)
		// simple wallet txs are always valid as standalone

		//random amount
		source := rand.NewSource(time.Now().UnixNano())
		random := rand.New(source)
		min := int64(1)
		max := int64(constants.TotalVaulted)
		randAmount := uint64(random.Int63n(max-min+1) + min)

		sourceGas := rand.NewSource(time.Now().UnixNano())
		randomGas := rand.New(sourceGas)
		maxGas := 3000
		randomGasNumber := uint64(randomGas.Int63n(int64(maxGas)) + 1)
		opts := []sdk.Opt{
			sdk.WithGenesisID(genesisID),
			sdk.WithGasPrice(randomGasNumber),
		}

		spw1 := sdkWallet.Spawn(privkeys[0], templateWallet.TemplateAddress, spawnArgsWallet, 0, opts...)
		spw2 := sdkWallet.SelfSpawn(privkeys[0], 0, opts...)
		spw3 := sdkWallet.SelfSpawn(privkeys[0], 0, opts...)
		spw4 := sdkWallet.Spend(privkeys[0], destination, constants.OneSmesh, 0, opts...)
		txList := []TxPair{
			{txtype: Spawn, tx: spw1, valid: true, genesisID: genesisID},
			{txtype: SelfSpawn, tx: spw2, valid: true, genesisID: genesisID},
			// apply the parsed self spawn tx
			// this will allow the spend tx to be validated
			{txtype: Ignore, tx: spw3, genesisID: genesisID},
			{txtype: Spend, tx: spw4, valid: true, genesisID: genesisID},
		}
		testVectors = append(testVectors, processTxList(txList, hrp, Wallet, len(testVectors), vm, destination, 1, 1, nil, constants.OneSmesh, templateVault.SpawnArguments{})...)

		// MULTISIG
		// 1-of-1, 1-of-2, 2-of-2
		log.Debug("TEMPLATE: MULTISIG")
		for n := uint8(1); n <= MaxKeys; n = n + 3 {
			// generate a fresh set of keys
			pubkeysSigning, pubkeysCore, pubkeysEd, privkeys := generateKeys(int(n))

			for m := uint8(1); m <= n; m = m + 4 {
				spawnArgsMultisig := &templateMultisig.SpawnArguments{
					Required:   m,
					PublicKeys: pubkeysCore[:n],
				}

				// calculate multisig principalMultisig address, which depends on the set of pubkeys
				principalMultisig := core.ComputePrincipal(templateMultisig.TemplateAddress, spawnArgsMultisig)

				randomGasNumber := uint64(randomGas.Int63n(int64(maxGas)) + 1)
				opts := []sdk.Opt{
					sdk.WithGenesisID(genesisID),
					sdk.WithGasPrice(randomGasNumber),
				}

				multisigTxList := handleMultisig(
					vm,
					opts,
					destination,
					hrp,
					templateMultisig.TemplateAddress,
					principalMultisig,
					spawnArgsMultisig,
					pubkeysSigning,
					pubkeysCore,
					pubkeysEd,
					privkeys,
					m,
					n,
					randAmount,
					genesisID,
				)
				testVectors = append(testVectors, processTxList(multisigTxList, hrp, Multisig, len(testVectors), vm, destination, m, n, spawnArgsMultisig.PublicKeys, randAmount, templateVault.SpawnArguments{})...)
			}
		}

		// VESTING
		// 1-of-1, 1-of-2, 2-of-2
		// vesting accounts are a superset of multisig. they can do everything a multisig can do, but
		// additionally they can drain a vault account.
		log.Debug("TEMPLATE: VESTING")
		for n := uint8(1); n <= MaxKeys; n = n + 2 {
			// generate a fresh set of keys
			pubkeysSigning, pubkeysCore, pubkeysEd, privkeys := generateKeys(int(n))

			for m := uint8(1); m <= n; m = m + 4 {
				// note: vesting uses multisig spawn arguments
				spawnArgsMultisig := &templateMultisig.SpawnArguments{
					Required:   m,
					PublicKeys: pubkeysCore[:n],
				}

				// calculate multisig principalMultisig address, which depends on the set of pubkeys
				principalMultisig := core.ComputePrincipal(templateVesting.TemplateAddress, spawnArgsMultisig)
				randAmount = uint64(random.Int63n(max-min+1) + min)
				randomGasNumber := uint64(randomGas.Int63n(int64(maxGas)) + 1)
				opts := []sdk.Opt{
					sdk.WithGenesisID(genesisID),
					sdk.WithGasPrice(randomGasNumber),
				}
				vestingTxList := handleMultisig(
					vm,
					opts,
					destination,
					hrp,
					templateVesting.TemplateAddress,
					principalMultisig,
					spawnArgsMultisig,
					pubkeysSigning,
					pubkeysCore,
					pubkeysEd,
					privkeys,
					m,
					n,
					randAmount,
					genesisID,
				)

				// add drain vault tx

				// first, calculate the vault address
				// just make up some arbitrary numbers here for the purposes of the test vectors

				initAmount := uint64(randomGas.Int63n(150000000/3) + 1)
				totalAmount := uint64(randomGas.Int63n(150000000/3)) + initAmount + 1

				vestingStart := uint32(randomGas.Int31n(5) + 1)
				vestingEnd := uint32(randomGas.Int63n(10)) + vestingStart + 1

				vaultArgs := &templateVault.SpawnArguments{
					Owner:               principalMultisig,
					TotalAmount:         totalAmount * constants.OneSmesh,
					InitialUnlockAmount: initAmount * constants.OneSmesh,
					VestingStart:        types.LayerID(vestingStart) * constants.OneYear,
					VestingEnd:          types.LayerID(vestingEnd) * constants.OneYear,
				}
				vaultAddr := core.ComputePrincipal(templateVault.TemplateAddress, vaultArgs)
				spawnVault := sdkMultisig.Spawn(0, privkeys[0], principalMultisig, templateVault.TemplateAddress, vaultArgs, 0, opts...)
				drainVaultAgg := sdkVesting.DrainVault(0, privkeys[0], principalMultisig, vaultAddr, destination, randAmount, 0, opts...)

				txDrainVault := make([]TxPair, 2)
				//txDrainVault := make([]TxPair, m)
				txDrainVault[0] = TxPair{txtype: Spawn, tx: spawnVault.Raw(), valid: m == 1, part: 0, vault: vaultAddr.String(), genesisID: genesisID}
				txDrainVault[1] = TxPair{txtype: Drain, tx: drainVaultAgg.Raw(), valid: m == 1, part: 0, vault: vaultAddr.String(), genesisID: genesisID}

				// TODO: Check this
				// for signerIdx := uint8(1); signerIdx < m; signerIdx++ {
				// 	drainVaultAgg.Add(*sdkVesting.DrainVault(signerIdx, privkeys[signerIdx], principalMultisig, vaultAddr, destination, Amount, 0, opts...).Part(signerIdx))
				// 	txDrainVault[signerIdx] = TxPair{txtype: Drain, tx: drainVaultAgg.Raw(), valid: signerIdx == m-1, part: signerIdx, vault: vaultAddr.String()}
				// }
				testVectors = append(testVectors, processTxList(vestingTxList, hrp, Vesting, len(testVectors), vm, destination, m, n, spawnArgsMultisig.PublicKeys, randAmount, *vaultArgs)...)
				testVectors = append(testVectors, processTxList(txDrainVault, hrp, Vault, len(testVectors), vm, destination, m, n, spawnArgsMultisig.PublicKeys, randAmount, *vaultArgs)...)
			}
		}
	}
	return testVectors
}

func main() {
	testVectors := generateTestVectors()

	jsonData, err := json.MarshalIndent(testVectors, "", "  ")
	if err != nil {
		log.Fatal("Error marshalling test vectors: %v", err)
	}

	fmt.Println(string(jsonData))

	// Write JSON to file
	err = writeJSONToFile("test.json", jsonData)
	if err != nil {
		log.Err(err)
	}

	createRawTestVector()
}

func writeJSONToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// func getKey() (pub signing.PublicKey, priv signing.PrivateKey) {
func getKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	// generate a random keypair
	pub, priv, err := ed25519.GenerateKey(rand.New(rand.NewSource(rand.Int63())))
	if err != nil {
		log.Fatal("failed to generate ed25519 key")
	}
	return
}

type rawSignedTx struct {
	Message string `json:"message"`
	Prefix  string `json:"prefix"`
	Domain  int    `json:"domain"`
}

type RawTestVector struct {
	Index  int      `json:"index"`
	Name   string   `json:"name"`
	Blob   string   `json:"blob"`
	Output []string `json:"output"`
}

const (
	ATX                 = 0
	PROPOSAL            = 1
	BEACON_FOLLOWUP_MSG = 11
)

var txTypeToString = map[int]string{
	ATX:                 "ATX",
	PROPOSAL:            "PROPOSAL",
	BEACON_FOLLOWUP_MSG: "BEACON FOLLOWUP MSG",
}

func txToString(txType int) string {
	if str, ok := txTypeToString[txType]; ok {
		return str
	}
	return "UNKNOWN"
}

func createRawTestVector() {
	messages := []string{"", "This is our test payload", "This is our test payload with emoji! 😉"}
	prefixes := []string{"", "prefix", "prefix 😉"}
	domains := []int{ATX, PROPOSAL, BEACON_FOLLOWUP_MSG}

	var testVectors []rawSignedTx
	for _, message := range messages {
		for _, prefix := range prefixes {
			for _, domain := range domains {
				tx := rawSignedTx{
					Message: message,
					Prefix:  prefix,
					Domain:  domain,
				}
				testVectors = append(testVectors, tx)
			}
		}
	}

	var outputTestVector []RawTestVector
	// Concatenate domain, prefix and message
	for i, tx := range testVectors {
		var buf bytes.Buffer
		prefixLength := uint16(len(tx.Prefix))
		binary.Write(&buf, binary.LittleEndian, prefixLength)
		messageLength := uint16(len(tx.Message))
		binary.Write(&buf, binary.LittleEndian, messageLength)
		buf.Write([]byte(tx.Prefix))
		buf.WriteByte(byte(tx.Domain))
		buf.Write([]byte(tx.Message))

		concatenated := buf.Bytes()

		// Convert concatenated string to hex
		blob := hex.EncodeToString([]byte(concatenated))

		if tx.Prefix == "" {
			tx.Prefix = "Empty"
		}
		if tx.Message == "" {
			tx.Message = "Empty"
		}
		prefixHex := ""
		if tx.Prefix == "prefix 😉" {
			tx.Prefix = hex.EncodeToString([]byte(tx.Prefix))
			prefixHex = "(hex) "
		}
		messageHex := ""
		if tx.Message == "This is our test payload with emoji! 😉" {
			tx.Message = hex.EncodeToString([]byte(tx.Message))
			messageHex = "(hex) "
		}

		// Create output array
		output := []string{
			"0 | Sign : Message",
			fmt.Sprintf("1 | Prefix %s: %s", prefixHex, tx.Prefix),
			fmt.Sprintf("2 | Domain : %s", txToString(tx.Domain)),
		}

		// Handle pagination for tx.Message
		if len(tx.Message) > 38 {
			for j := 0; j < len(tx.Message); j += 38 {
				end := j + 38
				if end > len(tx.Message) {
					end = len(tx.Message)
				}
				output = append(output, fmt.Sprintf("3 | Msg %s[%d/%d] : %s", messageHex, j/38+1, (len(tx.Message)+37)/38, tx.Message[j:end]))
			}
		} else {
			output = append(output, fmt.Sprintf("3 | Msg %s: %s", messageHex, tx.Message))
		}

		outputTestVector = append(outputTestVector, RawTestVector{
			Index:  i,
			Name:   fmt.Sprintf("raw_%d", i),
			Blob:   blob,
			Output: output,
		})
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(outputTestVector, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// Write JSON to file
	err = ioutil.WriteFile("rawTestVector.json", jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing JSON to file:", err)
		return
	}

}
