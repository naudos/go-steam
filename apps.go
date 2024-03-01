package steam

import (
	"github.com/0xAozora/go-steam/protocol"
	"github.com/0xAozora/go-steam/protocol/protobuf"
	"github.com/0xAozora/go-steam/protocol/steamlang"
)

func (c *Client) GetProductInfo(appID uint32) *protobuf.CMsgClientPICSProductInfoResponse {

	req := &protobuf.CMsgClientPICSProductInfoRequest{
		Apps: []*protobuf.CMsgClientPICSProductInfoRequest_AppInfo{
			{
				Appid: &appID,
			},
		},
	}

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientPICSProductInfoRequest, req)
	jobID := c.GetNextJobId()
	msg.SetSourceJobId(jobID)

	ch := make(chan *protobuf.CMsgClientPICSProductInfoResponse)

	c.JobMutex.Lock()
	c.JobHandlers[uint64(jobID)] = func(packet *protocol.Packet) error {
		body := new(protobuf.CMsgClientPICSProductInfoResponse)
		_ = packet.ReadProtoMsg(body)
		ch <- body
		return nil
	}
	c.JobMutex.Unlock()

	c.Send(msg)
	return <-ch
}
