package shell

import (
	"context"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"strconv"
	"time"

	utils "github.com/TRON-US/go-btfs-api/utils"
	"github.com/gogo/protobuf/proto"
	"github.com/tron-us/go-common/v2/json"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/tron-us/go-btfs-common/crypto"
	escrowpb "github.com/tron-us/go-btfs-common/protos/escrow"
	guardpb "github.com/tron-us/go-btfs-common/protos/guard"
	ledgerpb "github.com/tron-us/go-btfs-common/protos/ledger"
	cutils "github.com/tron-us/go-btfs-common/utils"
)

type StorageUploadOpts = func(*RequestBuilder) error

type storageUploadResponse struct {
	ID string
}

type Shard struct {
	ContractId string
	Price      int64
	Host       string
	Status     string
}

type Storage struct {
	Status   string
	Message  string
	FileHash string
	Shards   map[string]Shard
}

type ContractItem struct {
	Key      string `json:"key"`
	Contract string `json:"contract"`
}

type Contracts struct {
	Contracts []ContractItem `json:contracts`
}

type UnsignedData struct {
	Unsigned string
	Opcode   string
	Price    int64
}

type StorageOpts = func(*RequestBuilder) error

func UploadMode(mode string) StorageOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("m", mode)
		return nil
	}
}

func Hosts(hosts string) StorageOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("s", hosts)
		return nil
	}
}

func (d UnsignedData) SignData(privateKey string) ([]byte, error) {
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	signedData, err := privKey.Sign([]byte(d.Unsigned))
	if err != nil {
		return nil, err
	}
	return signedData, nil
}

func (d UnsignedData) SignBalanceData(privateKey string) (*ledgerpb.SignedPublicKey, error) {
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	pubKeyRaw, err := privKey.GetPublic().Raw()
	if err != nil {
		return nil, err
	}
	lgPubKey := &ledgerpb.PublicKey{
		Key: pubKeyRaw,
	}
	sig, err := crypto.Sign(privKey, lgPubKey)
	if err != nil {
		return nil, err
	}
	lgSignedPubKey := &ledgerpb.SignedPublicKey{
		Key:       lgPubKey,
		Signature: sig,
	}
	return lgSignedPubKey, nil
}

func (c Contracts) SignContracts(privateKey string, sessionStatus string) (*Contracts, error) {
	// Perform signing using private key
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	for idx, element := range c.Contracts {
		by, err := cutils.StringToBytes(element.Contract, cutils.Base64)
		if err != nil {
			return nil, err
		}
		var signedContract []byte
		if sessionStatus == "initSignReadyEscrow" {
			escrowContract := &escrowpb.EscrowContract{}

			err = proto.Unmarshal(by, escrowContract)
			if err != nil {
				return nil, err
			}
			signedContract, err = crypto.Sign(privKey, escrowContract)
			if err != nil {
				return nil, err
			}

		} else {
			guardContract := &guardpb.ContractMeta{}
			//var guardContract proto.Message
			err := proto.Unmarshal(by, guardContract)
			if err != nil {
				return nil, err
			}
			signedContract, err = crypto.Sign(privKey, guardContract)
			if err != nil {
				return nil, err
			}
			if DEBUG {
				err := verifyP2PMessage(signedContract, utils.GetPeerId())
				if err != nil {
					return nil, err
				}
			}
		}
		// This overwrites
		str, err := cutils.BytesToString(signedContract, cutils.Base64)
		if err != nil {
			return nil, err
		}
		c.Contracts[idx].Contract = str
		if err != nil {
			return nil, err
		}
	}

	return &c, nil
}
func UnmarshalGuardContract(marshaledBody []byte) (*guardpb.Contract, error) {
	signedContract := &guardpb.Contract{}
	err := proto.Unmarshal(marshaledBody, signedContract)
	if err != nil {
		return nil, err
	}
	return signedContract, nil
}

func verifyP2PMessage(signedContract []byte, offlinePeerId string) error {
	halfSignedGuardContBytes := signedContract
	halfSignedGuardContract, err := UnmarshalGuardContract(halfSignedGuardContBytes)
	if err != nil {
		fmt.Println("verifyP2PMessage error: UnmarshalG..")
		return err
	}

	guardContractMeta := halfSignedGuardContract.ContractMeta

	s := halfSignedGuardContract.GetRenterSignature()
	if s == nil {
		s = halfSignedGuardContract.GetPreparerSignature()
	}
	renterPid, err := peer.IDB58Decode(offlinePeerId)
	if err != nil {
		fmt.Println("verifyP2PMessage error: IDB58Decode..")
		return err
	}

	payerPubKey, err := renterPid.ExtractPublicKey()
	if err != nil {
		fmt.Println("verifyP2PMessage error: ExtractPublicKey.")
		return err
	}

	ok, err := crypto.Verify(payerPubKey, &guardContractMeta, s)
	if !ok || err != nil {
		fmt.Printf("verifyP2PMessage: can't verify guard contract: %v\n", err)
		return fmt.Errorf("verifyP2PMessage: can't verify guard contract: %v", err)
	}
	return nil
}

// Set storage upload time.
func StorageLength(length int) StorageUploadOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("storage-length", length)
		return nil
	}
}

func (s *Shell) GetUts() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func getSessionSignature(hash string, peerId string) (string, time.Time, error) {
	//offline session signature
	now := time.Now()
	sessionSignature := fmt.Sprintf("%s:%s:%s", utils.GetPeerId(), hash, "time.Now().String()")
	return sessionSignature, now, nil
}

// Storage upload api.
func (s *Shell) StorageUpload(hash string, options ...StorageUploadOpts) (string, error) {
	var out storageUploadResponse
	rb := s.Request("storage/upload", hash)
	for _, option := range options {
		_ = option(rb)
	}
	return out.ID, rb.Exec(context.Background(), &out)
}

// Storage upload api.
func (s *Shell) StorageUploadOffSign(hash string, uts string, options ...StorageUploadOpts) (string, error) {
	var out storageUploadResponse
	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return "", err
	}
	rb := s.Request("storage/upload/offline", hash, utils.GetPeerId(), uts, offlinePeerSessionSignature)
	for _, option := range options {
		_ = option(rb)
	}
	return out.ID, rb.Exec(context.Background(), &out)
}

// Storage upload status api.
func (s *Shell) StorageUploadStatus(id string) (*Storage, error) {
	var out Storage
	rb := s.Request("storage/upload/status", id)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload get offline contract batch api.
func (s *Shell) StorageUploadGetContractBatch(sid string, hash string, uts string, sessionStatus string) (*Contracts, error) {
	var out Contracts
	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return nil, err
	}
	rb := s.Request("storage/upload/getcontractbatch", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload get offline unsigned data api.
func (s *Shell) StorageUploadGetUnsignedData(sid string, hash string, uts string, sessionStatus string) (*UnsignedData, error) {
	var out UnsignedData
	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return nil, err
	}
	rb := s.Request("storage/upload/getunsigned", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload sign offline contract batch api.
func (s *Shell) StorageUploadSignBatch(sid string, hash string, unsignedBatchContracts *Contracts, uts string, sessionStatus string) error {
	var signedBatchContracts *Contracts
	var errSign error
	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return err
	}

	signedBatchContracts, errSign = unsignedBatchContracts.SignContracts(utils.GetPrivateKey(), sessionStatus)
	if errSign != nil {
		return err
	}
	bytesSignBatch, err := json.Marshal(signedBatchContracts.Contracts)
	if err != nil {
		return err
	}

	rb := s.Request("storage/upload/signcontractbatch", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature,
		sessionStatus, string(bytesSignBatch))
	return rb.Exec(context.Background(), nil)
}

const DEBUG = true

// Storage upload sign offline data api.
func (s *Shell) StorageUploadSign(id string, hash string, unsignedData *UnsignedData, uts string, sessionStatus string) ([]byte, error) {
	var out []byte
	var rb *RequestBuilder
	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return nil, err
	}
	signedBytes, err := unsignedData.SignData(utils.GetPrivateKey())
	if err != nil {
		return nil, err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, string(signedBytes), sessionStatus)
	return out, rb.Exec(context.Background(), &out)
}

func (s *Shell) StorageUploadSignBalance(id string, hash string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return err
	}

	ledgerSignedPublicKey, err := unsignedData.SignBalanceData(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	signedBytes, err := proto.Marshal(ledgerSignedPublicKey) // TODO: check if ic.Marshall is necessary!
	if err != nil {
		return err
	}
	str, err := cutils.BytesToString(signedBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, str, sessionStatus)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignPayChannel(id, hash string, unsignedData *UnsignedData, uts string, sessionStatus string, totalPrice int64) error {
	var rb *RequestBuilder
	offlinePeerSessionSignature, now, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return err
	}

	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	escrowPubKey, err := ic.UnmarshalPublicKey(unsignedBytes)
	if err != nil {
		return err
	}
	buyerPubKey, err := crypto.ToPubKey(utils.GetPublicKey())
	if err != nil {
		return err
	}
	fromAddr, err := ic.RawFull(buyerPubKey)
	if err != nil {
		return err
	}
	toAddr, err := ic.RawFull(escrowPubKey)
	if err != nil {
		return err
	}
	chanCommit := &ledgerpb.ChannelCommit{
		Payer:     &ledgerpb.PublicKey{Key: fromAddr},
		Recipient: &ledgerpb.PublicKey{Key: toAddr},
		Amount:    totalPrice,
		PayerId:   now.UnixNano(),
	}
	buyerPrivKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	buyerChanSig, err := crypto.Sign(buyerPrivKey, chanCommit)
	if err != nil {
		return err
	}
	signedChanCommit := &ledgerpb.SignedChannelCommit{
		Channel:   chanCommit,
		Signature: buyerChanSig,
	}
	signedChanCommitBytes, err := proto.Marshal(signedChanCommit)
	if err != nil {
		return err
	}
	signedChanCommitBytesStr, err := cutils.BytesToString(signedChanCommitBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, signedChanCommitBytesStr, sessionStatus)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignPayRequest(id, hash string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return err
	}

	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	result := new(escrowpb.SignedSubmitContractResult)
	err = proto.Unmarshal(unsignedBytes, result)
	if err != nil {
		return err
	}

	chanState := result.Result.BuyerChannelState
	privKey, _ := crypto.ToPrivKey(utils.GetPrivateKey())
	sig, err := crypto.Sign(privKey, chanState.Channel)
	if err != nil {
		return err
	}
	chanState.FromSignature = sig
	payerPubKey, _ := crypto.ToPubKey(utils.GetPublicKey())
	raw, err := ic.RawFull(payerPubKey)
	if err != nil {
		return err
	}
	payinReq := &escrowpb.PayinRequest{
		PayinId:           result.Result.PayinId,
		BuyerAddress:      raw,
		BuyerChannelState: chanState,
	}
	payinSig, err := crypto.Sign(privKey, payinReq)
	if err != nil {
		return err
	}
	signedPayinReq := &escrowpb.SignedPayinRequest{
		Request:        payinReq,
		BuyerSignature: payinSig,
	}

	signedPayinReqBytes, err := proto.Marshal(signedPayinReq)
	if err != nil {
		return err
	}

	str, err := cutils.BytesToString(signedPayinReqBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, str, sessionStatus)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignGuardFileMeta(id, hash string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, _, err := getSessionSignature(hash, utils.GetPeerId())
	if err != nil {
		return err
	}
	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	meta := new(guardpb.FileStoreMeta)
	err = proto.Unmarshal(unsignedBytes, meta)
	if err != nil {
		return err
	}

	privKey, _ := crypto.ToPrivKey(utils.GetPrivateKey())
	signed, err := crypto.Sign(privKey, meta)
	if err != nil {
		return err
	}

	str, err := cutils.BytesToString(signed, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, str, sessionStatus)
	return rb.Exec(context.Background(), nil)
}
