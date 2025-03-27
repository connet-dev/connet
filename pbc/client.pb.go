// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        v5.29.2
// source: client.proto

package pbc

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

type ProxyProtoVersion int32

const (
	ProxyProtoVersion_ProxyProtoNone ProxyProtoVersion = 0
	ProxyProtoVersion_V1             ProxyProtoVersion = 1
	ProxyProtoVersion_V2             ProxyProtoVersion = 2
)

// Enum value maps for ProxyProtoVersion.
var (
	ProxyProtoVersion_name = map[int32]string{
		0: "ProxyProtoNone",
		1: "V1",
		2: "V2",
	}
	ProxyProtoVersion_value = map[string]int32{
		"ProxyProtoNone": 0,
		"V1":             1,
		"V2":             2,
	}
)

func (x ProxyProtoVersion) Enum() *ProxyProtoVersion {
	p := new(ProxyProtoVersion)
	*p = x
	return p
}

func (x ProxyProtoVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProxyProtoVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_client_proto_enumTypes[0].Descriptor()
}

func (ProxyProtoVersion) Type() protoreflect.EnumType {
	return &file_client_proto_enumTypes[0]
}

func (x ProxyProtoVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProxyProtoVersion.Descriptor instead.
func (ProxyProtoVersion) EnumDescriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{0}
}

type RelayEncryptionScheme int32

const (
	RelayEncryptionScheme_EncryptionNone RelayEncryptionScheme = 0
	RelayEncryptionScheme_TLS            RelayEncryptionScheme = 1
)

// Enum value maps for RelayEncryptionScheme.
var (
	RelayEncryptionScheme_name = map[int32]string{
		0: "EncryptionNone",
		1: "TLS",
	}
	RelayEncryptionScheme_value = map[string]int32{
		"EncryptionNone": 0,
		"TLS":            1,
	}
)

func (x RelayEncryptionScheme) Enum() *RelayEncryptionScheme {
	p := new(RelayEncryptionScheme)
	*p = x
	return p
}

func (x RelayEncryptionScheme) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RelayEncryptionScheme) Descriptor() protoreflect.EnumDescriptor {
	return file_client_proto_enumTypes[1].Descriptor()
}

func (RelayEncryptionScheme) Type() protoreflect.EnumType {
	return &file_client_proto_enumTypes[1]
}

func (x RelayEncryptionScheme) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RelayEncryptionScheme.Descriptor instead.
func (RelayEncryptionScheme) EnumDescriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{1}
}

type Request struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Soft one-of
	Connect       *Request_Connect `protobuf:"bytes,1,opt,name=connect,proto3" json:"connect,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Request) Reset() {
	*x = Request{}
	mi := &file_client_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[0]
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
	return file_client_proto_rawDescGZIP(), []int{0}
}

func (x *Request) GetConnect() *Request_Connect {
	if x != nil {
		return x.Connect
	}
	return nil
}

type Response struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Error         *pb.Error              `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Connect       *Response_Connect      `protobuf:"bytes,2,opt,name=connect,proto3" json:"connect,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Response) Reset() {
	*x = Response{}
	mi := &file_client_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[1]
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
	return file_client_proto_rawDescGZIP(), []int{1}
}

func (x *Response) GetError() *pb.Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *Response) GetConnect() *Response_Connect {
	if x != nil {
		return x.Connect
	}
	return nil
}

type TLSConfiguration struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ClientName    string                 `protobuf:"bytes,1,opt,name=client_name,json=clientName,proto3" json:"client_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TLSConfiguration) Reset() {
	*x = TLSConfiguration{}
	mi := &file_client_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TLSConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TLSConfiguration) ProtoMessage() {}

func (x *TLSConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TLSConfiguration.ProtoReflect.Descriptor instead.
func (*TLSConfiguration) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{2}
}

func (x *TLSConfiguration) GetClientName() string {
	if x != nil {
		return x.ClientName
	}
	return ""
}

type Request_Connect struct {
	state            protoimpl.MessageState  `protogen:"open.v1"`
	SourceEncryption []RelayEncryptionScheme `protobuf:"varint,1,rep,packed,name=source_encryption,json=sourceEncryption,proto3,enum=client.RelayEncryptionScheme" json:"source_encryption,omitempty"`
	SourceTls        *TLSConfiguration       `protobuf:"bytes,2,opt,name=source_tls,json=sourceTls,proto3" json:"source_tls,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *Request_Connect) Reset() {
	*x = Request_Connect{}
	mi := &file_client_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_Connect) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_Connect) ProtoMessage() {}

func (x *Request_Connect) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request_Connect.ProtoReflect.Descriptor instead.
func (*Request_Connect) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Request_Connect) GetSourceEncryption() []RelayEncryptionScheme {
	if x != nil {
		return x.SourceEncryption
	}
	return nil
}

func (x *Request_Connect) GetSourceTls() *TLSConfiguration {
	if x != nil {
		return x.SourceTls
	}
	return nil
}

type Response_Connect struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	ProxyProto            ProxyProtoVersion      `protobuf:"varint,1,opt,name=proxy_proto,json=proxyProto,proto3,enum=client.ProxyProtoVersion" json:"proxy_proto,omitempty"`
	DestinationEncryption RelayEncryptionScheme  `protobuf:"varint,2,opt,name=destination_encryption,json=destinationEncryption,proto3,enum=client.RelayEncryptionScheme" json:"destination_encryption,omitempty"`
	DestinationTls        *TLSConfiguration      `protobuf:"bytes,3,opt,name=destination_tls,json=destinationTls,proto3" json:"destination_tls,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *Response_Connect) Reset() {
	*x = Response_Connect{}
	mi := &file_client_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response_Connect) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response_Connect) ProtoMessage() {}

func (x *Response_Connect) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response_Connect.ProtoReflect.Descriptor instead.
func (*Response_Connect) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Response_Connect) GetProxyProto() ProxyProtoVersion {
	if x != nil {
		return x.ProxyProto
	}
	return ProxyProtoVersion_ProxyProtoNone
}

func (x *Response_Connect) GetDestinationEncryption() RelayEncryptionScheme {
	if x != nil {
		return x.DestinationEncryption
	}
	return RelayEncryptionScheme_EncryptionNone
}

func (x *Response_Connect) GetDestinationTls() *TLSConfiguration {
	if x != nil {
		return x.DestinationTls
	}
	return nil
}

var File_client_proto protoreflect.FileDescriptor

var file_client_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcd, 0x01, 0x0a, 0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x31, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x1a, 0x8e, 0x01, 0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12,
	0x4a, 0x0a, 0x11, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x1d, 0x2e, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x52, 0x10, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x37, 0x0a, 0x0a, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x18, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x54, 0x4c, 0x53, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x54, 0x6c, 0x73, 0x22, 0xc4, 0x02, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x23, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0d, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x32, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x1a, 0xde, 0x01, 0x0a, 0x07, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12, 0x3a, 0x0a, 0x0b, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x54, 0x0a, 0x16, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x1d, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x6c, 0x61,
	0x79, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x63, 0x68, 0x65, 0x6d,
	0x65, 0x52, 0x15, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x41, 0x0a, 0x0f, 0x64, 0x65, 0x73, 0x74,
	0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x18, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x54, 0x4c, 0x53, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0e, 0x64, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x6c, 0x73, 0x22, 0x33, 0x0a, 0x10, 0x54,
	0x4c, 0x53, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65,
	0x2a, 0x37, 0x0a, 0x11, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x0e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72,
	0x6f, 0x74, 0x6f, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x56, 0x31, 0x10,
	0x01, 0x12, 0x06, 0x0a, 0x02, 0x56, 0x32, 0x10, 0x02, 0x2a, 0x34, 0x0a, 0x15, 0x52, 0x65, 0x6c,
	0x61, 0x79, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x63, 0x68, 0x65,
	0x6d, 0x65, 0x12, 0x12, 0x0a, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x54, 0x4c, 0x53, 0x10, 0x01, 0x42,
	0x22, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2f,
	0x70, 0x62, 0x63, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_client_proto_rawDescOnce sync.Once
	file_client_proto_rawDescData = file_client_proto_rawDesc
)

func file_client_proto_rawDescGZIP() []byte {
	file_client_proto_rawDescOnce.Do(func() {
		file_client_proto_rawDescData = protoimpl.X.CompressGZIP(file_client_proto_rawDescData)
	})
	return file_client_proto_rawDescData
}

var file_client_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_client_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_client_proto_goTypes = []any{
	(ProxyProtoVersion)(0),     // 0: client.ProxyProtoVersion
	(RelayEncryptionScheme)(0), // 1: client.RelayEncryptionScheme
	(*Request)(nil),            // 2: client.Request
	(*Response)(nil),           // 3: client.Response
	(*TLSConfiguration)(nil),   // 4: client.TLSConfiguration
	(*Request_Connect)(nil),    // 5: client.Request.Connect
	(*Response_Connect)(nil),   // 6: client.Response.Connect
	(*pb.Error)(nil),           // 7: shared.Error
}
var file_client_proto_depIdxs = []int32{
	5, // 0: client.Request.connect:type_name -> client.Request.Connect
	7, // 1: client.Response.error:type_name -> shared.Error
	6, // 2: client.Response.connect:type_name -> client.Response.Connect
	1, // 3: client.Request.Connect.source_encryption:type_name -> client.RelayEncryptionScheme
	4, // 4: client.Request.Connect.source_tls:type_name -> client.TLSConfiguration
	0, // 5: client.Response.Connect.proxy_proto:type_name -> client.ProxyProtoVersion
	1, // 6: client.Response.Connect.destination_encryption:type_name -> client.RelayEncryptionScheme
	4, // 7: client.Response.Connect.destination_tls:type_name -> client.TLSConfiguration
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_client_proto_init() }
func file_client_proto_init() {
	if File_client_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_client_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_client_proto_goTypes,
		DependencyIndexes: file_client_proto_depIdxs,
		EnumInfos:         file_client_proto_enumTypes,
		MessageInfos:      file_client_proto_msgTypes,
	}.Build()
	File_client_proto = out.File
	file_client_proto_rawDesc = nil
	file_client_proto_goTypes = nil
	file_client_proto_depIdxs = nil
}
