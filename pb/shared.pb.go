// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        v5.29.2
// source: shared.proto

package pb

import (
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

type Role int32

const (
	Role_RoleUnknown     Role = 0
	Role_RoleDestination Role = 1
	Role_RoleSource      Role = 2
)

// Enum value maps for Role.
var (
	Role_name = map[int32]string{
		0: "RoleUnknown",
		1: "RoleDestination",
		2: "RoleSource",
	}
	Role_value = map[string]int32{
		"RoleUnknown":     0,
		"RoleDestination": 1,
		"RoleSource":      2,
	}
)

func (x Role) Enum() *Role {
	p := new(Role)
	*p = x
	return p
}

func (x Role) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Role) Descriptor() protoreflect.EnumDescriptor {
	return file_shared_proto_enumTypes[0].Descriptor()
}

func (Role) Type() protoreflect.EnumType {
	return &file_shared_proto_enumTypes[0]
}

func (x Role) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Role.Descriptor instead.
func (Role) EnumDescriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{0}
}

type Error_Code int32

const (
	// Generic
	Error_Unknown        Error_Code = 0
	Error_RequestUnknown Error_Code = 1
	Error_CheckFailed    Error_Code = 2
	// Authentication
	Error_AuthenticationFailed Error_Code = 100
	Error_ForwardNotAllowed    Error_Code = 101
	Error_RoleNotAllowed       Error_Code = 102
	// Announce
	Error_AnnounceValidationFailed         Error_Code = 200
	Error_AnnounceInvalidClientCertificate Error_Code = 201
	Error_AnnounceInvalidServerCertificate Error_Code = 202
	// Relay
	Error_RelayValidationFailed   Error_Code = 300
	Error_RelayInvalidCertificate Error_Code = 301
	Error_RelayKeepaliveClosed    Error_Code = 302
	// Direct
	Error_DirectConnectionClosed Error_Code = 400
	Error_DirectKeepaliveClosed  Error_Code = 401
	// Client connect codes
	Error_DestinationNotFound             Error_Code = 500
	Error_DestinationDialFailed           Error_Code = 501
	Error_DestinationRelayEncryptionError Error_Code = 502
)

// Enum value maps for Error_Code.
var (
	Error_Code_name = map[int32]string{
		0:   "Unknown",
		1:   "RequestUnknown",
		2:   "CheckFailed",
		100: "AuthenticationFailed",
		101: "ForwardNotAllowed",
		102: "RoleNotAllowed",
		200: "AnnounceValidationFailed",
		201: "AnnounceInvalidClientCertificate",
		202: "AnnounceInvalidServerCertificate",
		300: "RelayValidationFailed",
		301: "RelayInvalidCertificate",
		302: "RelayKeepaliveClosed",
		400: "DirectConnectionClosed",
		401: "DirectKeepaliveClosed",
		500: "DestinationNotFound",
		501: "DestinationDialFailed",
		502: "DestinationRelayEncryptionError",
	}
	Error_Code_value = map[string]int32{
		"Unknown":                          0,
		"RequestUnknown":                   1,
		"CheckFailed":                      2,
		"AuthenticationFailed":             100,
		"ForwardNotAllowed":                101,
		"RoleNotAllowed":                   102,
		"AnnounceValidationFailed":         200,
		"AnnounceInvalidClientCertificate": 201,
		"AnnounceInvalidServerCertificate": 202,
		"RelayValidationFailed":            300,
		"RelayInvalidCertificate":          301,
		"RelayKeepaliveClosed":             302,
		"DirectConnectionClosed":           400,
		"DirectKeepaliveClosed":            401,
		"DestinationNotFound":              500,
		"DestinationDialFailed":            501,
		"DestinationRelayEncryptionError":  502,
	}
)

func (x Error_Code) Enum() *Error_Code {
	p := new(Error_Code)
	*p = x
	return p
}

func (x Error_Code) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Error_Code) Descriptor() protoreflect.EnumDescriptor {
	return file_shared_proto_enumTypes[1].Descriptor()
}

func (Error_Code) Type() protoreflect.EnumType {
	return &file_shared_proto_enumTypes[1]
}

func (x Error_Code) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Error_Code.Descriptor instead.
func (Error_Code) EnumDescriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{4, 0}
}

type Addr struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	V4            []byte                 `protobuf:"bytes,1,opt,name=v4,proto3" json:"v4,omitempty"`
	V6            []byte                 `protobuf:"bytes,2,opt,name=v6,proto3" json:"v6,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Addr) Reset() {
	*x = Addr{}
	mi := &file_shared_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Addr) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Addr) ProtoMessage() {}

func (x *Addr) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Addr.ProtoReflect.Descriptor instead.
func (*Addr) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{0}
}

func (x *Addr) GetV4() []byte {
	if x != nil {
		return x.V4
	}
	return nil
}

func (x *Addr) GetV6() []byte {
	if x != nil {
		return x.V6
	}
	return nil
}

type AddrPort struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Addr          *Addr                  `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
	Port          uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"` // really uint16, but not a thing in protobuf
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AddrPort) Reset() {
	*x = AddrPort{}
	mi := &file_shared_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AddrPort) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddrPort) ProtoMessage() {}

func (x *AddrPort) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddrPort.ProtoReflect.Descriptor instead.
func (*AddrPort) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{1}
}

func (x *AddrPort) GetAddr() *Addr {
	if x != nil {
		return x.Addr
	}
	return nil
}

func (x *AddrPort) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

type HostPort struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Host          string                 `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Port          uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HostPort) Reset() {
	*x = HostPort{}
	mi := &file_shared_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HostPort) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostPort) ProtoMessage() {}

func (x *HostPort) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostPort.ProtoReflect.Descriptor instead.
func (*HostPort) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{2}
}

func (x *HostPort) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *HostPort) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

type Forward struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Forward) Reset() {
	*x = Forward{}
	mi := &file_shared_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Forward) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Forward) ProtoMessage() {}

func (x *Forward) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Forward.ProtoReflect.Descriptor instead.
func (*Forward) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{3}
}

func (x *Forward) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type Error struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Code          Error_Code             `protobuf:"varint,1,opt,name=code,proto3,enum=shared.Error_Code" json:"code,omitempty"`
	Message       string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Error) Reset() {
	*x = Error{}
	mi := &file_shared_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{4}
}

func (x *Error) GetCode() Error_Code {
	if x != nil {
		return x.Code
	}
	return Error_Unknown
}

func (x *Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_shared_proto protoreflect.FileDescriptor

var file_shared_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x22, 0x26, 0x0a, 0x04, 0x41, 0x64, 0x64, 0x72, 0x12, 0x0e,
	0x0a, 0x02, 0x76, 0x34, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x76, 0x34, 0x12, 0x0e,
	0x0a, 0x02, 0x76, 0x36, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x76, 0x36, 0x22, 0x40,
	0x0a, 0x08, 0x41, 0x64, 0x64, 0x72, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x20, 0x0a, 0x04, 0x61, 0x64,
	0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65,
	0x64, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x12, 0x12, 0x0a, 0x04,
	0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74,
	0x22, 0x32, 0x0a, 0x08, 0x48, 0x6f, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04,
	0x70, 0x6f, 0x72, 0x74, 0x22, 0x1d, 0x0a, 0x07, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x22, 0xa0, 0x04, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x26, 0x0a,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x73, 0x68,
	0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x43, 0x6f, 0x64, 0x65, 0x52,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22,
	0xd4, 0x03, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x6e, 0x6b, 0x6e,
	0x6f, 0x77, 0x6e, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x68, 0x65,
	0x63, 0x6b, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0x02, 0x12, 0x18, 0x0a, 0x14, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c,
	0x65, 0x64, 0x10, 0x64, 0x12, 0x15, 0x0a, 0x11, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x4e,
	0x6f, 0x74, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x10, 0x65, 0x12, 0x12, 0x0a, 0x0e, 0x52,
	0x6f, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x10, 0x66, 0x12,
	0x1d, 0x0a, 0x18, 0x41, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x56, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xc8, 0x01, 0x12, 0x25,
	0x0a, 0x20, 0x41, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x10, 0xc9, 0x01, 0x12, 0x25, 0x0a, 0x20, 0x41, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63,
	0x65, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x10, 0xca, 0x01, 0x12, 0x1a, 0x0a, 0x15,
	0x52, 0x65, 0x6c, 0x61, 0x79, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46,
	0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xac, 0x02, 0x12, 0x1c, 0x0a, 0x17, 0x52, 0x65, 0x6c, 0x61,
	0x79, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x10, 0xad, 0x02, 0x12, 0x19, 0x0a, 0x14, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x4b,
	0x65, 0x65, 0x70, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x10, 0xae,
	0x02, 0x12, 0x1b, 0x0a, 0x16, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x10, 0x90, 0x03, 0x12, 0x1a,
	0x0a, 0x15, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x4b, 0x65, 0x65, 0x70, 0x61, 0x6c, 0x69, 0x76,
	0x65, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x10, 0x91, 0x03, 0x12, 0x18, 0x0a, 0x13, 0x44, 0x65,
	0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e,
	0x64, 0x10, 0xf4, 0x03, 0x12, 0x1a, 0x0a, 0x15, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x44, 0x69, 0x61, 0x6c, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xf5, 0x03,
	0x12, 0x24, 0x0a, 0x1f, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x6c, 0x61, 0x79, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x10, 0xf6, 0x03, 0x2a, 0x3c, 0x0a, 0x04, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x0f,
	0x0a, 0x0b, 0x52, 0x6f, 0x6c, 0x65, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x10, 0x00, 0x12,
	0x13, 0x0a, 0x0f, 0x52, 0x6f, 0x6c, 0x65, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x52, 0x6f, 0x6c, 0x65, 0x53, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x10, 0x02, 0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x74, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_shared_proto_rawDescOnce sync.Once
	file_shared_proto_rawDescData = file_shared_proto_rawDesc
)

func file_shared_proto_rawDescGZIP() []byte {
	file_shared_proto_rawDescOnce.Do(func() {
		file_shared_proto_rawDescData = protoimpl.X.CompressGZIP(file_shared_proto_rawDescData)
	})
	return file_shared_proto_rawDescData
}

var file_shared_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_shared_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_shared_proto_goTypes = []any{
	(Role)(0),        // 0: shared.Role
	(Error_Code)(0),  // 1: shared.Error.Code
	(*Addr)(nil),     // 2: shared.Addr
	(*AddrPort)(nil), // 3: shared.AddrPort
	(*HostPort)(nil), // 4: shared.HostPort
	(*Forward)(nil),  // 5: shared.Forward
	(*Error)(nil),    // 6: shared.Error
}
var file_shared_proto_depIdxs = []int32{
	2, // 0: shared.AddrPort.addr:type_name -> shared.Addr
	1, // 1: shared.Error.code:type_name -> shared.Error.Code
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_shared_proto_init() }
func file_shared_proto_init() {
	if File_shared_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_shared_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_shared_proto_goTypes,
		DependencyIndexes: file_shared_proto_depIdxs,
		EnumInfos:         file_shared_proto_enumTypes,
		MessageInfos:      file_shared_proto_msgTypes,
	}.Build()
	File_shared_proto = out.File
	file_shared_proto_rawDesc = nil
	file_shared_proto_goTypes = nil
	file_shared_proto_depIdxs = nil
}
