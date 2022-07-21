package model

type Message struct {
	MessageHeader MessageHeader `json:"h"`
	MessageBody   MessageBody `json:"b"`
}

type NodePublicKey struct {
	PublicKey []byte `json:"k"`
}

type MessageHeader struct {
	MemberId       string                    `json:"m"`
	PublicKey      *[]byte                   `json:"k"`
	NodePublicKeys *map[string]NodePublicKey `json:"l"`
}

type MessageBody struct {
	RawPayload    string `json:"-"`
	CipherPayload []byte `json:"p"`
}
