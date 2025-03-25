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
	ProxyProtoVersion_None ProxyProtoVersion = 0
	ProxyProtoVersion_V1   ProxyProtoVersion = 1
	ProxyProtoVersion_V2   ProxyProtoVersion = 2
)

// Enum value maps for ProxyProtoVersion.
var (
	ProxyProtoVersion_name = map[int32]string{
		0: "None",
		1: "V1",
		2: "V2",
	}
	ProxyProtoVersion_value = map[string]int32{
		"None": 0,
		"V1":   1,
		"V2":   2,
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

type Request_Connect struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	SourceClientName string                 `protobuf:"bytes,1,opt,name=source_client_name,json=sourceClientName,proto3" json:"source_client_name,omitempty"`
	SourceClientKey  []byte                 `protobuf:"bytes,2,opt,name=source_client_key,json=sourceClientKey,proto3" json:"source_client_key,omitempty"`
	SourceClientSign []byte                 `protobuf:"bytes,3,opt,name=source_client_sign,json=sourceClientSign,proto3" json:"source_client_sign,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *Request_Connect) Reset() {
	*x = Request_Connect{}
	mi := &file_client_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Request_Connect) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request_Connect) ProtoMessage() {}

func (x *Request_Connect) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Request_Connect.ProtoReflect.Descriptor instead.
func (*Request_Connect) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Request_Connect) GetSourceClientName() string {
	if x != nil {
		return x.SourceClientName
	}
	return ""
}

func (x *Request_Connect) GetSourceClientKey() []byte {
	if x != nil {
		return x.SourceClientKey
	}
	return nil
}

func (x *Request_Connect) GetSourceClientSign() []byte {
	if x != nil {
		return x.SourceClientSign
	}
	return nil
}

type Response_Connect struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	ProxyProto            ProxyProtoVersion      `protobuf:"varint,1,opt,name=proxy_proto,json=proxyProto,proto3,enum=client.ProxyProtoVersion" json:"proxy_proto,omitempty"`
	DestinationClientName string                 `protobuf:"bytes,2,opt,name=destination_client_name,json=destinationClientName,proto3" json:"destination_client_name,omitempty"`
	DestinationClientKey  []byte                 `protobuf:"bytes,3,opt,name=destination_client_key,json=destinationClientKey,proto3" json:"destination_client_key,omitempty"`
	DestinationClientSign []byte                 `protobuf:"bytes,4,opt,name=destination_client_sign,json=destinationClientSign,proto3" json:"destination_client_sign,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *Response_Connect) Reset() {
	*x = Response_Connect{}
	mi := &file_client_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response_Connect) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response_Connect) ProtoMessage() {}

func (x *Response_Connect) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Response_Connect.ProtoReflect.Descriptor instead.
func (*Response_Connect) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Response_Connect) GetProxyProto() ProxyProtoVersion {
	if x != nil {
		return x.ProxyProto
	}
	return ProxyProtoVersion_None
}

func (x *Response_Connect) GetDestinationClientName() string {
	if x != nil {
		return x.DestinationClientName
	}
	return ""
}

func (x *Response_Connect) GetDestinationClientKey() []byte {
	if x != nil {
		return x.DestinationClientKey
	}
	return nil
}

func (x *Response_Connect) GetDestinationClientSign() []byte {
	if x != nil {
		return x.DestinationClientSign
	}
	return nil
}

var File_client_proto protoreflect.FileDescriptor

var file_client_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x1a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd0, 0x01, 0x0a, 0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x31, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x1a, 0x91, 0x01, 0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12,
	0x2c, 0x0a, 0x12, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a,
	0x11, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x2c, 0x0a, 0x12, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x22, 0xd1, 0x02, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x23, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72,
	0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x32, 0x0a, 0x07, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x1a, 0xeb, 0x01,
	0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12, 0x3a, 0x0a, 0x0b, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19,
	0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x36, 0x0a, 0x17, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, 0x0a,
	0x16, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x64,
	0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x4b, 0x65, 0x79, 0x12, 0x36, 0x0a, 0x17, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x15, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x2a, 0x2d, 0x0a, 0x11, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x08, 0x0a, 0x04, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x56, 0x31,
	0x10, 0x01, 0x12, 0x06, 0x0a, 0x02, 0x56, 0x32, 0x10, 0x02, 0x42, 0x22, 0x5a, 0x20, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2d,
	0x64, 0x65, 0x76, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2f, 0x70, 0x62, 0x63, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_client_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_client_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_client_proto_goTypes = []any{
	(ProxyProtoVersion)(0),   // 0: client.ProxyProtoVersion
	(*Request)(nil),          // 1: client.Request
	(*Response)(nil),         // 2: client.Response
	(*Request_Connect)(nil),  // 3: client.Request.Connect
	(*Response_Connect)(nil), // 4: client.Response.Connect
	(*pb.Error)(nil),         // 5: shared.Error
}
var file_client_proto_depIdxs = []int32{
	3, // 0: client.Request.connect:type_name -> client.Request.Connect
	5, // 1: client.Response.error:type_name -> shared.Error
	4, // 2: client.Response.connect:type_name -> client.Response.Connect
	0, // 3: client.Response.Connect.proxy_proto:type_name -> client.ProxyProtoVersion
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
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
			NumEnums:      1,
			NumMessages:   4,
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
