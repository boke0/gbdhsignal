package model

type Message struct {
	MessageHeader MessageHeader
	MessageBody   MessageBody
}

type NodePublicKey struct {
	NodeId    string
	PublicKey []byte
}

type MessageHeader struct {
	MemberId       string
	PublicKey      *[]byte
	NodePublicKeys *map[string]NodePublicKey
}

type MessageBody struct {
	RawPayload    string
	CipherPayload []byte
}
