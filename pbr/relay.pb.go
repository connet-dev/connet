// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.1
// 	protoc        v5.29.1
// source: relay.proto

package pbr

import (
	pb "github.com/connet-dev/connet/pb"
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

type ChangeType int32

const (
	ChangeType_ChangeUnknown ChangeType = 0
	ChangeType_ChangePut     ChangeType = 1
	ChangeType_ChangeDel     ChangeType = 2
)

// Enum value maps for ChangeType.
var (
	ChangeType_name = map[int32]string{
		0: "ChangeUnknown",
		1: "ChangePut",
		2: "ChangeDel",
	}
	ChangeType_value = map[string]int32{
		"ChangeUnknown": 0,
		"ChangePut":     1,
		"ChangeDel":     2,
	}
)

func (x ChangeType) Enum() *ChangeType {
	p := new(ChangeType)
	*p = x
	return p
}

func (x ChangeType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ChangeType) Descriptor() protoreflect.EnumDescriptor {
	return file_relay_proto_enumTypes[0].Descriptor()
}

func (ChangeType) Type() protoreflect.EnumType {
	return &file_relay_proto_enumTypes[0]
}

func (x ChangeType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ChangeType.Descriptor instead.
func (ChangeType) EnumDescriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{0}
}

type AuthenticateReq struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Token          string                 `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	Addr           *pb.HostPort           `protobuf:"bytes,2,opt,name=addr,proto3" json:"addr,omitempty"`
	ReconnectToken []byte                 `protobuf:"bytes,3,opt,name=reconnect_token,json=reconnectToken,proto3" json:"reconnect_token,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *AuthenticateReq) Reset() {
	*x = AuthenticateReq{}
	mi := &file_relay_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthenticateReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateReq) ProtoMessage() {}

func (x *AuthenticateReq) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateReq.ProtoReflect.Descriptor instead.
func (*AuthenticateReq) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{0}
}

func (x *AuthenticateReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *AuthenticateReq) GetAddr() *pb.HostPort {
	if x != nil {
		return x.Addr
	}
	return nil
}

func (x *AuthenticateReq) GetReconnectToken() []byte {
	if x != nil {
		return x.ReconnectToken
	}
	return nil
}

type AuthenticateResp struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Error          *pb.Error              `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	ControlId      string                 `protobuf:"bytes,2,opt,name=control_id,json=controlId,proto3" json:"control_id,omitempty"`
	ReconnectToken []byte                 `protobuf:"bytes,3,opt,name=reconnect_token,json=reconnectToken,proto3" json:"reconnect_token,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *AuthenticateResp) Reset() {
	*x = AuthenticateResp{}
	mi := &file_relay_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthenticateResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateResp) ProtoMessage() {}

func (x *AuthenticateResp) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[1]
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
	return file_relay_proto_rawDescGZIP(), []int{1}
}

func (x *AuthenticateResp) GetError() *pb.Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *AuthenticateResp) GetControlId() string {
	if x != nil {
		return x.ControlId
	}
	return ""
}

func (x *AuthenticateResp) GetReconnectToken() []byte {
	if x != nil {
		return x.ReconnectToken
	}
	return nil
}

type ClientsReq struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Offset        int64                  `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ClientsReq) Reset() {
	*x = ClientsReq{}
	mi := &file_relay_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientsReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientsReq) ProtoMessage() {}

func (x *ClientsReq) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientsReq.ProtoReflect.Descriptor instead.
func (*ClientsReq) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{2}
}

func (x *ClientsReq) GetOffset() int64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

type ClientsResp struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Changes       []*ClientsResp_Change  `protobuf:"bytes,1,rep,name=changes,proto3" json:"changes,omitempty"`
	Offset        int64                  `protobuf:"varint,2,opt,name=offset,proto3" json:"offset,omitempty"`
	Restart       bool                   `protobuf:"varint,3,opt,name=restart,proto3" json:"restart,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ClientsResp) Reset() {
	*x = ClientsResp{}
	mi := &file_relay_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientsResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientsResp) ProtoMessage() {}

func (x *ClientsResp) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientsResp.ProtoReflect.Descriptor instead.
func (*ClientsResp) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{3}
}

func (x *ClientsResp) GetChanges() []*ClientsResp_Change {
	if x != nil {
		return x.Changes
	}
	return nil
}

func (x *ClientsResp) GetOffset() int64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

func (x *ClientsResp) GetRestart() bool {
	if x != nil {
		return x.Restart
	}
	return false
}

type ServersReq struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Offset        int64                  `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ServersReq) Reset() {
	*x = ServersReq{}
	mi := &file_relay_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServersReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServersReq) ProtoMessage() {}

func (x *ServersReq) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServersReq.ProtoReflect.Descriptor instead.
func (*ServersReq) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{4}
}

func (x *ServersReq) GetOffset() int64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

type ServersResp struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Changes       []*ServersResp_Change  `protobuf:"bytes,1,rep,name=changes,proto3" json:"changes,omitempty"`
	Offset        int64                  `protobuf:"varint,2,opt,name=offset,proto3" json:"offset,omitempty"`
	Restart       bool                   `protobuf:"varint,3,opt,name=restart,proto3" json:"restart,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ServersResp) Reset() {
	*x = ServersResp{}
	mi := &file_relay_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServersResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServersResp) ProtoMessage() {}

func (x *ServersResp) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServersResp.ProtoReflect.Descriptor instead.
func (*ServersResp) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{5}
}

func (x *ServersResp) GetChanges() []*ServersResp_Change {
	if x != nil {
		return x.Changes
	}
	return nil
}

func (x *ServersResp) GetOffset() int64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

func (x *ServersResp) GetRestart() bool {
	if x != nil {
		return x.Restart
	}
	return false
}

type ClientsResp_Change struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Change         ChangeType             `protobuf:"varint,1,opt,name=change,proto3,enum=relay.ChangeType" json:"change,omitempty"`
	Forward        *pb.Forward            `protobuf:"bytes,2,opt,name=forward,proto3" json:"forward,omitempty"`
	Role           pb.Role                `protobuf:"varint,3,opt,name=role,proto3,enum=shared.Role" json:"role,omitempty"`
	CertificateKey string                 `protobuf:"bytes,4,opt,name=certificate_key,json=certificateKey,proto3" json:"certificate_key,omitempty"`
	Certificate    []byte                 `protobuf:"bytes,5,opt,name=certificate,proto3" json:"certificate,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ClientsResp_Change) Reset() {
	*x = ClientsResp_Change{}
	mi := &file_relay_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientsResp_Change) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientsResp_Change) ProtoMessage() {}

func (x *ClientsResp_Change) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientsResp_Change.ProtoReflect.Descriptor instead.
func (*ClientsResp_Change) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{3, 0}
}

func (x *ClientsResp_Change) GetChange() ChangeType {
	if x != nil {
		return x.Change
	}
	return ChangeType_ChangeUnknown
}

func (x *ClientsResp_Change) GetForward() *pb.Forward {
	if x != nil {
		return x.Forward
	}
	return nil
}

func (x *ClientsResp_Change) GetRole() pb.Role {
	if x != nil {
		return x.Role
	}
	return pb.Role(0)
}

func (x *ClientsResp_Change) GetCertificateKey() string {
	if x != nil {
		return x.CertificateKey
	}
	return ""
}

func (x *ClientsResp_Change) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

type ServersResp_Change struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	Change            ChangeType             `protobuf:"varint,1,opt,name=change,proto3,enum=relay.ChangeType" json:"change,omitempty"`
	Forward           *pb.Forward            `protobuf:"bytes,2,opt,name=forward,proto3" json:"forward,omitempty"`
	ServerCertificate []byte                 `protobuf:"bytes,3,opt,name=server_certificate,json=serverCertificate,proto3" json:"server_certificate,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *ServersResp_Change) Reset() {
	*x = ServersResp_Change{}
	mi := &file_relay_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServersResp_Change) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServersResp_Change) ProtoMessage() {}

func (x *ServersResp_Change) ProtoReflect() protoreflect.Message {
	mi := &file_relay_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServersResp_Change.ProtoReflect.Descriptor instead.
func (*ServersResp_Change) Descriptor() ([]byte, []int) {
	return file_relay_proto_rawDescGZIP(), []int{5, 0}
}

func (x *ServersResp_Change) GetChange() ChangeType {
	if x != nil {
		return x.Change
	}
	return ChangeType_ChangeUnknown
}

func (x *ServersResp_Change) GetForward() *pb.Forward {
	if x != nil {
		return x.Forward
	}
	return nil
}

func (x *ServersResp_Change) GetServerCertificate() []byte {
	if x != nil {
		return x.ServerCertificate
	}
	return nil
}

var File_relay_proto protoreflect.FileDescriptor

var file_relay_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x72,
	0x65, 0x6c, 0x61, 0x79, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x76, 0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x24, 0x0a, 0x04, 0x61,
	0x64, 0x64, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x68, 0x61, 0x72,
	0x65, 0x64, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x04, 0x61, 0x64, 0x64,
	0x72, 0x12, 0x27, 0x0a, 0x0f, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x5f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x72, 0x65, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x7f, 0x0a, 0x10, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x12, 0x23,
	0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72,
	0x72, 0x6f, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x49, 0x64, 0x12, 0x27, 0x0a, 0x0f, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x5f,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x72, 0x65, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x24, 0x0a, 0x0a, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x71, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66,
	0x73, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65,
	0x74, 0x22, 0xc2, 0x02, 0x0a, 0x0b, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x12, 0x33, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x07, 0x63,
	0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x12, 0x18,
	0x0a, 0x07, 0x72, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x07, 0x72, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x1a, 0xcb, 0x01, 0x0a, 0x06, 0x43, 0x68, 0x61,
	0x6e, 0x67, 0x65, 0x12, 0x29, 0x0a, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x11, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2e, 0x43, 0x68, 0x61, 0x6e,
	0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x29,
	0x0a, 0x07, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64,
	0x52, 0x07, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x12, 0x20, 0x0a, 0x04, 0x72, 0x6f, 0x6c,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x2e, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x63,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x22, 0x24, 0x0a, 0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x73, 0x52, 0x65, 0x71, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x22, 0x84, 0x02, 0x0a,
	0x0b, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x12, 0x33, 0x0a, 0x07,
	0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x72, 0x65, 0x6c, 0x61, 0x79, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x73, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x72, 0x65, 0x73, 0x74,
	0x61, 0x72, 0x74, 0x1a, 0x8d, 0x01, 0x0a, 0x06, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x29,
	0x0a, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x11,
	0x2e, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x52, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x29, 0x0a, 0x07, 0x66, 0x6f, 0x72,
	0x77, 0x61, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x68, 0x61,
	0x72, 0x65, 0x64, 0x2e, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x07, 0x66, 0x6f, 0x72,
	0x77, 0x61, 0x72, 0x64, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x63,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x11, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x2a, 0x3d, 0x0a, 0x0a, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x11, 0x0a, 0x0d, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x55, 0x6e, 0x6b, 0x6e, 0x6f,
	0x77, 0x6e, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x75,
	0x74, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x44, 0x65, 0x6c,
	0x10, 0x02, 0x42, 0x22, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x74, 0x2f, 0x70, 0x62, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_relay_proto_rawDescOnce sync.Once
	file_relay_proto_rawDescData = file_relay_proto_rawDesc
)

func file_relay_proto_rawDescGZIP() []byte {
	file_relay_proto_rawDescOnce.Do(func() {
		file_relay_proto_rawDescData = protoimpl.X.CompressGZIP(file_relay_proto_rawDescData)
	})
	return file_relay_proto_rawDescData
}

var file_relay_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_relay_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_relay_proto_goTypes = []any{
	(ChangeType)(0),            // 0: relay.ChangeType
	(*AuthenticateReq)(nil),    // 1: relay.AuthenticateReq
	(*AuthenticateResp)(nil),   // 2: relay.AuthenticateResp
	(*ClientsReq)(nil),         // 3: relay.ClientsReq
	(*ClientsResp)(nil),        // 4: relay.ClientsResp
	(*ServersReq)(nil),         // 5: relay.ServersReq
	(*ServersResp)(nil),        // 6: relay.ServersResp
	(*ClientsResp_Change)(nil), // 7: relay.ClientsResp.Change
	(*ServersResp_Change)(nil), // 8: relay.ServersResp.Change
	(*pb.HostPort)(nil),        // 9: shared.HostPort
	(*pb.Error)(nil),           // 10: shared.Error
	(*pb.Forward)(nil),         // 11: shared.Forward
	(pb.Role)(0),               // 12: shared.Role
}
var file_relay_proto_depIdxs = []int32{
	9,  // 0: relay.AuthenticateReq.addr:type_name -> shared.HostPort
	10, // 1: relay.AuthenticateResp.error:type_name -> shared.Error
	7,  // 2: relay.ClientsResp.changes:type_name -> relay.ClientsResp.Change
	8,  // 3: relay.ServersResp.changes:type_name -> relay.ServersResp.Change
	0,  // 4: relay.ClientsResp.Change.change:type_name -> relay.ChangeType
	11, // 5: relay.ClientsResp.Change.forward:type_name -> shared.Forward
	12, // 6: relay.ClientsResp.Change.role:type_name -> shared.Role
	0,  // 7: relay.ServersResp.Change.change:type_name -> relay.ChangeType
	11, // 8: relay.ServersResp.Change.forward:type_name -> shared.Forward
	9,  // [9:9] is the sub-list for method output_type
	9,  // [9:9] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_relay_proto_init() }
func file_relay_proto_init() {
	if File_relay_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_relay_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_relay_proto_goTypes,
		DependencyIndexes: file_relay_proto_depIdxs,
		EnumInfos:         file_relay_proto_enumTypes,
		MessageInfos:      file_relay_proto_msgTypes,
	}.Build()
	File_relay_proto = out.File
	file_relay_proto_rawDesc = nil
	file_relay_proto_goTypes = nil
	file_relay_proto_depIdxs = nil
}
