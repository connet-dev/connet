// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.2
// source: server.proto

package pbs

import (
	pb "github.com/keihaya-com/connet/pb"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Authenticate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *Authenticate) Reset() {
	*x = Authenticate{}
	mi := &file_server_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Authenticate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Authenticate) ProtoMessage() {}

func (x *Authenticate) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Authenticate.ProtoReflect.Descriptor instead.
func (*Authenticate) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{0}
}

func (x *Authenticate) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type AuthenticateResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error  *pb.Error    `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Public *pb.AddrPort `protobuf:"bytes,2,opt,name=public,proto3" json:"public,omitempty"`
}

func (x *AuthenticateResp) Reset() {
	*x = AuthenticateResp{}
	mi := &file_server_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthenticateResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateResp) ProtoMessage() {}

func (x *AuthenticateResp) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateResp.ProtoReflect.Descriptor instead.
func (*AuthenticateResp) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{1}
}

func (x *AuthenticateResp) GetError() *pb.Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *AuthenticateResp) GetPublic() *pb.AddrPort {
	if x != nil {
		return x.Public
	}
	return nil
}

type Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Soft one-of
	DestinationRelay *Request_DestinationRelay `protobuf:"bytes,1,opt,name=destination_relay,json=destinationRelay,proto3" json:"destination_relay,omitempty"`
	Destination      *Request_Destination      `protobuf:"bytes,2,opt,name=destination,proto3" json:"destination,omitempty"`
	SourceRelay      *Request_SourceRelay      `protobuf:"bytes,3,opt,name=source_relay,json=sourceRelay,proto3" json:"source_relay,omitempty"`
	Source           *Request_Source           `protobuf:"bytes,4,opt,name=source,proto3" json:"source,omitempty"`
}

func (x *Request) Reset() {
	*x = Request{}
	mi := &file_server_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request.ProtoReflect.Descriptor instead.
func (*Request) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2}
}

func (x *Request) GetDestinationRelay() *Request_DestinationRelay {
	if x != nil {
		return x.DestinationRelay
	}
	return nil
}

func (x *Request) GetDestination() *Request_Destination {
	if x != nil {
		return x.Destination
	}
	return nil
}

func (x *Request) GetSourceRelay() *Request_SourceRelay {
	if x != nil {
		return x.SourceRelay
	}
	return nil
}

func (x *Request) GetSource() *Request_Source {
	if x != nil {
		return x.Source
	}
	return nil
}

type Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error       *pb.Error             `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Relay       *Response_Relay       `protobuf:"bytes,2,opt,name=relay,proto3" json:"relay,omitempty"`
	Destination *Response_Destination `protobuf:"bytes,3,opt,name=destination,proto3" json:"destination,omitempty"`
	Source      *Response_Source      `protobuf:"bytes,4,opt,name=source,proto3" json:"source,omitempty"`
}

func (x *Response) Reset() {
	*x = Response{}
	mi := &file_server_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{3}
}

func (x *Response) GetError() *pb.Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *Response) GetRelay() *Response_Relay {
	if x != nil {
		return x.Relay
	}
	return nil
}

func (x *Response) GetDestination() *Response_Destination {
	if x != nil {
		return x.Destination
	}
	return nil
}

func (x *Response) GetSource() *Response_Source {
	if x != nil {
		return x.Source
	}
	return nil
}

type ClientPeer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Direct *DirectRoute  `protobuf:"bytes,1,opt,name=direct,proto3" json:"direct,omitempty"`
	Relays []*RelayRoute `protobuf:"bytes,2,rep,name=relays,proto3" json:"relays,omitempty"`
}

func (x *ClientPeer) Reset() {
	*x = ClientPeer{}
	mi := &file_server_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientPeer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientPeer) ProtoMessage() {}

func (x *ClientPeer) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientPeer.ProtoReflect.Descriptor instead.
func (*ClientPeer) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{4}
}

func (x *ClientPeer) GetDirect() *DirectRoute {
	if x != nil {
		return x.Direct
	}
	return nil
}

func (x *ClientPeer) GetRelays() []*RelayRoute {
	if x != nil {
		return x.Relays
	}
	return nil
}

type ServerPeer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id     string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Direct *DirectRoute  `protobuf:"bytes,2,opt,name=direct,proto3" json:"direct,omitempty"`
	Relays []*RelayRoute `protobuf:"bytes,3,rep,name=relays,proto3" json:"relays,omitempty"`
}

func (x *ServerPeer) Reset() {
	*x = ServerPeer{}
	mi := &file_server_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServerPeer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerPeer) ProtoMessage() {}

func (x *ServerPeer) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServerPeer.ProtoReflect.Descriptor instead.
func (*ServerPeer) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{5}
}

func (x *ServerPeer) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ServerPeer) GetDirect() *DirectRoute {
	if x != nil {
		return x.Direct
	}
	return nil
}

func (x *ServerPeer) GetRelays() []*RelayRoute {
	if x != nil {
		return x.Relays
	}
	return nil
}

type DirectRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addresses         []*pb.AddrPort `protobuf:"bytes,1,rep,name=addresses,proto3" json:"addresses,omitempty"`
	ServerCertificate []byte         `protobuf:"bytes,2,opt,name=server_certificate,json=serverCertificate,proto3" json:"server_certificate,omitempty"`
	ClientCertificate []byte         `protobuf:"bytes,3,opt,name=client_certificate,json=clientCertificate,proto3" json:"client_certificate,omitempty"`
}

func (x *DirectRoute) Reset() {
	*x = DirectRoute{}
	mi := &file_server_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DirectRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DirectRoute) ProtoMessage() {}

func (x *DirectRoute) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DirectRoute.ProtoReflect.Descriptor instead.
func (*DirectRoute) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{6}
}

func (x *DirectRoute) GetAddresses() []*pb.AddrPort {
	if x != nil {
		return x.Addresses
	}
	return nil
}

func (x *DirectRoute) GetServerCertificate() []byte {
	if x != nil {
		return x.ServerCertificate
	}
	return nil
}

func (x *DirectRoute) GetClientCertificate() []byte {
	if x != nil {
		return x.ClientCertificate
	}
	return nil
}

type RelayRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address           *pb.HostPort `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	ServerCertificate []byte       `protobuf:"bytes,2,opt,name=server_certificate,json=serverCertificate,proto3" json:"server_certificate,omitempty"`
}

func (x *RelayRoute) Reset() {
	*x = RelayRoute{}
	mi := &file_server_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RelayRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RelayRoute) ProtoMessage() {}

func (x *RelayRoute) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RelayRoute.ProtoReflect.Descriptor instead.
func (*RelayRoute) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{7}
}

func (x *RelayRoute) GetAddress() *pb.HostPort {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *RelayRoute) GetServerCertificate() []byte {
	if x != nil {
		return x.ServerCertificate
	}
	return nil
}

type Request_DestinationRelay struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From        *pb.Forward `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	Certificate []byte      `protobuf:"bytes,2,opt,name=certificate,proto3" json:"certificate,omitempty"` // certificate to use when connecting to a relay
}

func (x *Request_DestinationRelay) Reset() {
	*x = Request_DestinationRelay{}
	mi := &file_server_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_DestinationRelay) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_DestinationRelay) ProtoMessage() {}

func (x *Request_DestinationRelay) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request_DestinationRelay.ProtoReflect.Descriptor instead.
func (*Request_DestinationRelay) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2, 0}
}

func (x *Request_DestinationRelay) GetFrom() *pb.Forward {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *Request_DestinationRelay) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

type Request_Destination struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From        *pb.Forward `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	Destination *ClientPeer `protobuf:"bytes,2,opt,name=destination,proto3" json:"destination,omitempty"`
}

func (x *Request_Destination) Reset() {
	*x = Request_Destination{}
	mi := &file_server_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_Destination) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_Destination) ProtoMessage() {}

func (x *Request_Destination) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request_Destination.ProtoReflect.Descriptor instead.
func (*Request_Destination) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2, 1}
}

func (x *Request_Destination) GetFrom() *pb.Forward {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *Request_Destination) GetDestination() *ClientPeer {
	if x != nil {
		return x.Destination
	}
	return nil
}

type Request_SourceRelay struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	To          *pb.Forward `protobuf:"bytes,1,opt,name=to,proto3" json:"to,omitempty"`
	Certificate []byte      `protobuf:"bytes,2,opt,name=certificate,proto3" json:"certificate,omitempty"` // certificate to use when connecting to a relay
}

func (x *Request_SourceRelay) Reset() {
	*x = Request_SourceRelay{}
	mi := &file_server_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_SourceRelay) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_SourceRelay) ProtoMessage() {}

func (x *Request_SourceRelay) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request_SourceRelay.ProtoReflect.Descriptor instead.
func (*Request_SourceRelay) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2, 2}
}

func (x *Request_SourceRelay) GetTo() *pb.Forward {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *Request_SourceRelay) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

type Request_Source struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	To     *pb.Forward `protobuf:"bytes,1,opt,name=to,proto3" json:"to,omitempty"`
	Source *ClientPeer `protobuf:"bytes,2,opt,name=source,proto3" json:"source,omitempty"`
}

func (x *Request_Source) Reset() {
	*x = Request_Source{}
	mi := &file_server_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_Source) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_Source) ProtoMessage() {}

func (x *Request_Source) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request_Source.ProtoReflect.Descriptor instead.
func (*Request_Source) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2, 3}
}

func (x *Request_Source) GetTo() *pb.Forward {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *Request_Source) GetSource() *ClientPeer {
	if x != nil {
		return x.Source
	}
	return nil
}

type Response_Relay struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Relays []*RelayRoute `protobuf:"bytes,1,rep,name=relays,proto3" json:"relays,omitempty"`
}

func (x *Response_Relay) Reset() {
	*x = Response_Relay{}
	mi := &file_server_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response_Relay) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response_Relay) ProtoMessage() {}

func (x *Response_Relay) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response_Relay.ProtoReflect.Descriptor instead.
func (*Response_Relay) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{3, 0}
}

func (x *Response_Relay) GetRelays() []*RelayRoute {
	if x != nil {
		return x.Relays
	}
	return nil
}

type Response_Destination struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Peers []*ServerPeer `protobuf:"bytes,1,rep,name=peers,proto3" json:"peers,omitempty"`
}

func (x *Response_Destination) Reset() {
	*x = Response_Destination{}
	mi := &file_server_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response_Destination) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response_Destination) ProtoMessage() {}

func (x *Response_Destination) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response_Destination.ProtoReflect.Descriptor instead.
func (*Response_Destination) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{3, 1}
}

func (x *Response_Destination) GetPeers() []*ServerPeer {
	if x != nil {
		return x.Peers
	}
	return nil
}

type Response_Source struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Peers []*ServerPeer `protobuf:"bytes,1,rep,name=peers,proto3" json:"peers,omitempty"`
}

func (x *Response_Source) Reset() {
	*x = Response_Source{}
	mi := &file_server_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response_Source) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response_Source) ProtoMessage() {}

func (x *Response_Source) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response_Source.ProtoReflect.Descriptor instead.
func (*Response_Source) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{3, 2}
}

func (x *Response_Source) GetPeers() []*ServerPeer {
	if x != nil {
		return x.Peers
	}
	return nil
}

var File_server_proto protoreflect.FileDescriptor

var file_server_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x24, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x61, 0x0a, 0x10, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x12, 0x23,
	0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72,
	0x72, 0x6f, 0x72, 0x12, 0x28, 0x0a, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x41, 0x64, 0x64,
	0x72, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0xf5, 0x04,
	0x0a, 0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x4d, 0x0a, 0x11, 0x64, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x10, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x3d, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x74,
	0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x44,
	0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x74,
	0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x0b, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x2e, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52,
	0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x1a, 0x59, 0x0a, 0x10, 0x44, 0x65, 0x73, 0x74, 0x69,
	0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x23, 0x0a, 0x04, 0x66,
	0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x68, 0x61, 0x72,
	0x65, 0x64, 0x2e, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d,
	0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x1a, 0x68, 0x0a, 0x0b, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x23, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64,
	0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x34, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x65, 0x65, 0x72, 0x52,
	0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x50, 0x0a, 0x0b,
	0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x1f, 0x0a, 0x02, 0x74,
	0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x2e, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x20, 0x0a, 0x0b,
	0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x1a, 0x55,
	0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1f, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x46, 0x6f,
	0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x2a, 0x0a, 0x06, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x65, 0x65, 0x72, 0x52, 0x06, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xf0, 0x02, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x23, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72,
	0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2c, 0x0a, 0x05, 0x72, 0x65, 0x6c, 0x61, 0x79,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x05,
	0x72, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x3e, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x44, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x06,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x1a, 0x33, 0x0a, 0x05, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x12,
	0x2a, 0x0a, 0x06, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x12, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x6f,
	0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x73, 0x1a, 0x37, 0x0a, 0x0b, 0x44,
	0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x05, 0x70, 0x65,
	0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x65, 0x65, 0x72, 0x52, 0x05, 0x70,
	0x65, 0x65, 0x72, 0x73, 0x1a, 0x32, 0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x28,
	0x0a, 0x05, 0x70, 0x65, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x65, 0x65,
	0x72, 0x52, 0x05, 0x70, 0x65, 0x65, 0x72, 0x73, 0x22, 0x65, 0x0a, 0x0a, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x50, 0x65, 0x65, 0x72, 0x12, 0x2b, 0x0a, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e,
	0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x64, 0x69, 0x72,
	0x65, 0x63, 0x74, 0x12, 0x2a, 0x0a, 0x06, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x6c,
	0x61, 0x79, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x73, 0x22,
	0x75, 0x0a, 0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x65, 0x65, 0x72, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x2b, 0x0a,
	0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x52, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x12, 0x2a, 0x0a, 0x06, 0x72, 0x65,
	0x6c, 0x61, 0x79, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06,
	0x72, 0x65, 0x6c, 0x61, 0x79, 0x73, 0x22, 0x9b, 0x01, 0x0a, 0x0b, 0x44, 0x69, 0x72, 0x65, 0x63,
	0x74, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x2e, 0x0a, 0x09, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x68, 0x61, 0x72,
	0x65, 0x64, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x09, 0x61, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x11, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f,
	0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x11, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x22, 0x67, 0x0a, 0x0a, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x12, 0x2a, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x48, 0x6f, 0x73,
	0x74, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2d,
	0x0a, 0x12, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x42, 0x23, 0x5a,
	0x21, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x65, 0x69, 0x68,
	0x61, 0x79, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2f, 0x70,
	0x62, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_server_proto_rawDescOnce sync.Once
	file_server_proto_rawDescData = file_server_proto_rawDesc
)

func file_server_proto_rawDescGZIP() []byte {
	file_server_proto_rawDescOnce.Do(func() {
		file_server_proto_rawDescData = protoimpl.X.CompressGZIP(file_server_proto_rawDescData)
	})
	return file_server_proto_rawDescData
}

var file_server_proto_msgTypes = make([]protoimpl.MessageInfo, 15)
var file_server_proto_goTypes = []any{
	(*Authenticate)(nil),             // 0: server.Authenticate
	(*AuthenticateResp)(nil),         // 1: server.AuthenticateResp
	(*Request)(nil),                  // 2: server.Request
	(*Response)(nil),                 // 3: server.Response
	(*ClientPeer)(nil),               // 4: server.ClientPeer
	(*ServerPeer)(nil),               // 5: server.ServerPeer
	(*DirectRoute)(nil),              // 6: server.DirectRoute
	(*RelayRoute)(nil),               // 7: server.RelayRoute
	(*Request_DestinationRelay)(nil), // 8: server.Request.DestinationRelay
	(*Request_Destination)(nil),      // 9: server.Request.Destination
	(*Request_SourceRelay)(nil),      // 10: server.Request.SourceRelay
	(*Request_Source)(nil),           // 11: server.Request.Source
	(*Response_Relay)(nil),           // 12: server.Response.Relay
	(*Response_Destination)(nil),     // 13: server.Response.Destination
	(*Response_Source)(nil),          // 14: server.Response.Source
	(*pb.Error)(nil),                 // 15: shared.Error
	(*pb.AddrPort)(nil),              // 16: shared.AddrPort
	(*pb.HostPort)(nil),              // 17: shared.HostPort
	(*pb.Forward)(nil),               // 18: shared.Forward
}
var file_server_proto_depIdxs = []int32{
	15, // 0: server.AuthenticateResp.error:type_name -> shared.Error
	16, // 1: server.AuthenticateResp.public:type_name -> shared.AddrPort
	8,  // 2: server.Request.destination_relay:type_name -> server.Request.DestinationRelay
	9,  // 3: server.Request.destination:type_name -> server.Request.Destination
	10, // 4: server.Request.source_relay:type_name -> server.Request.SourceRelay
	11, // 5: server.Request.source:type_name -> server.Request.Source
	15, // 6: server.Response.error:type_name -> shared.Error
	12, // 7: server.Response.relay:type_name -> server.Response.Relay
	13, // 8: server.Response.destination:type_name -> server.Response.Destination
	14, // 9: server.Response.source:type_name -> server.Response.Source
	6,  // 10: server.ClientPeer.direct:type_name -> server.DirectRoute
	7,  // 11: server.ClientPeer.relays:type_name -> server.RelayRoute
	6,  // 12: server.ServerPeer.direct:type_name -> server.DirectRoute
	7,  // 13: server.ServerPeer.relays:type_name -> server.RelayRoute
	16, // 14: server.DirectRoute.addresses:type_name -> shared.AddrPort
	17, // 15: server.RelayRoute.address:type_name -> shared.HostPort
	18, // 16: server.Request.DestinationRelay.from:type_name -> shared.Forward
	18, // 17: server.Request.Destination.from:type_name -> shared.Forward
	4,  // 18: server.Request.Destination.destination:type_name -> server.ClientPeer
	18, // 19: server.Request.SourceRelay.to:type_name -> shared.Forward
	18, // 20: server.Request.Source.to:type_name -> shared.Forward
	4,  // 21: server.Request.Source.source:type_name -> server.ClientPeer
	7,  // 22: server.Response.Relay.relays:type_name -> server.RelayRoute
	5,  // 23: server.Response.Destination.peers:type_name -> server.ServerPeer
	5,  // 24: server.Response.Source.peers:type_name -> server.ServerPeer
	25, // [25:25] is the sub-list for method output_type
	25, // [25:25] is the sub-list for method input_type
	25, // [25:25] is the sub-list for extension type_name
	25, // [25:25] is the sub-list for extension extendee
	0,  // [0:25] is the sub-list for field type_name
}

func init() { file_server_proto_init() }
func file_server_proto_init() {
	if File_server_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_server_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   15,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_server_proto_goTypes,
		DependencyIndexes: file_server_proto_depIdxs,
		MessageInfos:      file_server_proto_msgTypes,
	}.Build()
	File_server_proto = out.File
	file_server_proto_rawDesc = nil
	file_server_proto_goTypes = nil
	file_server_proto_depIdxs = nil
}
