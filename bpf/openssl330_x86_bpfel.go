// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type Openssl330ConnEvtT struct {
	ConnInfo Openssl330ConnInfoT
	ConnType Openssl330ConnTypeT
	_        [4]byte
	Ts       uint64
}

type Openssl330ConnIdS_t struct {
	TgidFd  uint64
	NoTrace bool
	_       [7]byte
}

type Openssl330ConnInfoT struct {
	ConnId struct {
		Upid struct {
			Pid            uint32
			_              [4]byte
			StartTimeTicks uint64
		}
		Fd   int32
		_    [4]byte
		Tsid uint64
	}
	ReadBytes     uint64
	WriteBytes    uint64
	SslReadBytes  uint64
	SslWriteBytes uint64
	Laddr         struct {
		In6 struct {
			Sin6Family   uint16
			Sin6Port     uint16
			Sin6Flowinfo uint32
			Sin6Addr     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			Sin6ScopeId  uint32
		}
	}
	Raddr struct {
		In6 struct {
			Sin6Family   uint16
			Sin6Port     uint16
			Sin6Flowinfo uint32
			Sin6Addr     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			Sin6ScopeId  uint32
		}
	}
	Protocol            Openssl330TrafficProtocolT
	Role                Openssl330EndpointRoleT
	PrevCount           uint64
	PrevBuf             [4]int8
	PrependLengthHeader bool
	NoTrace             bool
	Ssl                 bool
	_                   [1]byte
}

type Openssl330ConnTypeT uint32

const (
	Openssl330ConnTypeTKConnect       Openssl330ConnTypeT = 0
	Openssl330ConnTypeTKClose         Openssl330ConnTypeT = 1
	Openssl330ConnTypeTKProtocolInfer Openssl330ConnTypeT = 2
)

type Openssl330ControlValueIndexT uint32

const (
	Openssl330ControlValueIndexTKTargetTGIDIndex          Openssl330ControlValueIndexT = 0
	Openssl330ControlValueIndexTKStirlingTGIDIndex        Openssl330ControlValueIndexT = 1
	Openssl330ControlValueIndexTKEnabledXdpIndex          Openssl330ControlValueIndexT = 2
	Openssl330ControlValueIndexTKEnableFilterByPid        Openssl330ControlValueIndexT = 3
	Openssl330ControlValueIndexTKEnableFilterByLocalPort  Openssl330ControlValueIndexT = 4
	Openssl330ControlValueIndexTKEnableFilterByRemotePort Openssl330ControlValueIndexT = 5
	Openssl330ControlValueIndexTKEnableFilterByRemoteHost Openssl330ControlValueIndexT = 6
	Openssl330ControlValueIndexTKNumControlValues         Openssl330ControlValueIndexT = 7
)

type Openssl330EndpointRoleT uint32

const (
	Openssl330EndpointRoleTKRoleClient  Openssl330EndpointRoleT = 1
	Openssl330EndpointRoleTKRoleServer  Openssl330EndpointRoleT = 2
	Openssl330EndpointRoleTKRoleUnknown Openssl330EndpointRoleT = 4
)

type Openssl330KernEvt struct {
	FuncName [16]int8
	Ts       uint64
	Seq      uint64
	Len      uint32
	Flags    uint8
	_        [3]byte
	ConnIdS  Openssl330ConnIdS_t
	IsSample int32
	Step     Openssl330StepT
}

type Openssl330KernEvtData struct {
	Ke      Openssl330KernEvt
	BufSize uint32
	Msg     [30720]int8
	_       [4]byte
}

type Openssl330SockKey struct {
	Sip   [2]uint64
	Dip   [2]uint64
	Sport uint16
	Dport uint16
	_     [4]byte
}

type Openssl330StepT uint32

const (
	Openssl330StepTStart       Openssl330StepT = 0
	Openssl330StepTSSL_OUT     Openssl330StepT = 1
	Openssl330StepTSYSCALL_OUT Openssl330StepT = 2
	Openssl330StepTTCP_OUT     Openssl330StepT = 3
	Openssl330StepTIP_OUT      Openssl330StepT = 4
	Openssl330StepTQDISC_OUT   Openssl330StepT = 5
	Openssl330StepTDEV_OUT     Openssl330StepT = 6
	Openssl330StepTNIC_OUT     Openssl330StepT = 7
	Openssl330StepTNIC_IN      Openssl330StepT = 8
	Openssl330StepTDEV_IN      Openssl330StepT = 9
	Openssl330StepTIP_IN       Openssl330StepT = 10
	Openssl330StepTTCP_IN      Openssl330StepT = 11
	Openssl330StepTUSER_COPY   Openssl330StepT = 12
	Openssl330StepTSYSCALL_IN  Openssl330StepT = 13
	Openssl330StepTSSL_IN      Openssl330StepT = 14
	Openssl330StepTEnd         Openssl330StepT = 15
)

type Openssl330TrafficDirectionT uint32

const (
	Openssl330TrafficDirectionTKEgress  Openssl330TrafficDirectionT = 0
	Openssl330TrafficDirectionTKIngress Openssl330TrafficDirectionT = 1
)

type Openssl330TrafficProtocolT uint32

const (
	Openssl330TrafficProtocolTKProtocolUnset   Openssl330TrafficProtocolT = 0
	Openssl330TrafficProtocolTKProtocolUnknown Openssl330TrafficProtocolT = 1
	Openssl330TrafficProtocolTKProtocolHTTP    Openssl330TrafficProtocolT = 2
	Openssl330TrafficProtocolTKProtocolHTTP2   Openssl330TrafficProtocolT = 3
	Openssl330TrafficProtocolTKProtocolMySQL   Openssl330TrafficProtocolT = 4
	Openssl330TrafficProtocolTKProtocolCQL     Openssl330TrafficProtocolT = 5
	Openssl330TrafficProtocolTKProtocolPGSQL   Openssl330TrafficProtocolT = 6
	Openssl330TrafficProtocolTKProtocolDNS     Openssl330TrafficProtocolT = 7
	Openssl330TrafficProtocolTKProtocolRedis   Openssl330TrafficProtocolT = 8
	Openssl330TrafficProtocolTKProtocolNATS    Openssl330TrafficProtocolT = 9
	Openssl330TrafficProtocolTKProtocolMongo   Openssl330TrafficProtocolT = 10
	Openssl330TrafficProtocolTKProtocolKafka   Openssl330TrafficProtocolT = 11
	Openssl330TrafficProtocolTKProtocolMux     Openssl330TrafficProtocolT = 12
	Openssl330TrafficProtocolTKProtocolAMQP    Openssl330TrafficProtocolT = 13
	Openssl330TrafficProtocolTKNumProtocols    Openssl330TrafficProtocolT = 14
)

// LoadOpenssl330 returns the embedded CollectionSpec for Openssl330.
func LoadOpenssl330() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Openssl330Bytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Openssl330: %w", err)
	}

	return spec, err
}

// LoadOpenssl330Objects loads Openssl330 and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*Openssl330Objects
//	*Openssl330Programs
//	*Openssl330Maps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadOpenssl330Objects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadOpenssl330()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// Openssl330Specs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl330Specs struct {
	Openssl330ProgramSpecs
	Openssl330MapSpecs
}

// Openssl330Specs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl330ProgramSpecs struct {
	SSL_readEntryNestedSyscall    *ebpf.ProgramSpec `ebpf:"SSL_read_entry_nested_syscall"`
	SSL_readEntryOffset           *ebpf.ProgramSpec `ebpf:"SSL_read_entry_offset"`
	SSL_readExEntryNestedSyscall  *ebpf.ProgramSpec `ebpf:"SSL_read_ex_entry_nested_syscall"`
	SSL_readExRetNestedSyscall    *ebpf.ProgramSpec `ebpf:"SSL_read_ex_ret_nested_syscall"`
	SSL_readRetNestedSyscall      *ebpf.ProgramSpec `ebpf:"SSL_read_ret_nested_syscall"`
	SSL_readRetOffset             *ebpf.ProgramSpec `ebpf:"SSL_read_ret_offset"`
	SSL_writeEntryNestedSyscall   *ebpf.ProgramSpec `ebpf:"SSL_write_entry_nested_syscall"`
	SSL_writeEntryOffset          *ebpf.ProgramSpec `ebpf:"SSL_write_entry_offset"`
	SSL_writeExEntryNestedSyscall *ebpf.ProgramSpec `ebpf:"SSL_write_ex_entry_nested_syscall"`
	SSL_writeExRetNestedSyscall   *ebpf.ProgramSpec `ebpf:"SSL_write_ex_ret_nested_syscall"`
	SSL_writeRetNestedSyscall     *ebpf.ProgramSpec `ebpf:"SSL_write_ret_nested_syscall"`
	SSL_writeRetOffset            *ebpf.ProgramSpec `ebpf:"SSL_write_ret_offset"`
}

// Openssl330MapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Openssl330MapSpecs struct {
	ActiveSslReadArgsMap  *ebpf.MapSpec `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.MapSpec `ebpf:"active_ssl_write_args_map"`
	ConnEvtRb             *ebpf.MapSpec `ebpf:"conn_evt_rb"`
	ConnInfoMap           *ebpf.MapSpec `ebpf:"conn_info_map"`
	FilterMntnsMap        *ebpf.MapSpec `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.MapSpec `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.MapSpec `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.MapSpec `ebpf:"filter_pidns_map"`
	Rb                    *ebpf.MapSpec `ebpf:"rb"`
	SslDataMap            *ebpf.MapSpec `ebpf:"ssl_data_map"`
	SslRb                 *ebpf.MapSpec `ebpf:"ssl_rb"`
	SslUserSpaceCallMap   *ebpf.MapSpec `ebpf:"ssl_user_space_call_map"`
	SyscallDataMap        *ebpf.MapSpec `ebpf:"syscall_data_map"`
	SyscallRb             *ebpf.MapSpec `ebpf:"syscall_rb"`
}

// Openssl330Objects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl330Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl330Objects struct {
	Openssl330Programs
	Openssl330Maps
}

func (o *Openssl330Objects) Close() error {
	return _Openssl330Close(
		&o.Openssl330Programs,
		&o.Openssl330Maps,
	)
}

// Openssl330Maps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl330Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl330Maps struct {
	ActiveSslReadArgsMap  *ebpf.Map `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.Map `ebpf:"active_ssl_write_args_map"`
	ConnEvtRb             *ebpf.Map `ebpf:"conn_evt_rb"`
	ConnInfoMap           *ebpf.Map `ebpf:"conn_info_map"`
	FilterMntnsMap        *ebpf.Map `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.Map `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.Map `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.Map `ebpf:"filter_pidns_map"`
	Rb                    *ebpf.Map `ebpf:"rb"`
	SslDataMap            *ebpf.Map `ebpf:"ssl_data_map"`
	SslRb                 *ebpf.Map `ebpf:"ssl_rb"`
	SslUserSpaceCallMap   *ebpf.Map `ebpf:"ssl_user_space_call_map"`
	SyscallDataMap        *ebpf.Map `ebpf:"syscall_data_map"`
	SyscallRb             *ebpf.Map `ebpf:"syscall_rb"`
}

func (m *Openssl330Maps) Close() error {
	return _Openssl330Close(
		m.ActiveSslReadArgsMap,
		m.ActiveSslWriteArgsMap,
		m.ConnEvtRb,
		m.ConnInfoMap,
		m.FilterMntnsMap,
		m.FilterNetnsMap,
		m.FilterPidMap,
		m.FilterPidnsMap,
		m.Rb,
		m.SslDataMap,
		m.SslRb,
		m.SslUserSpaceCallMap,
		m.SyscallDataMap,
		m.SyscallRb,
	)
}

// Openssl330Programs contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadOpenssl330Objects or ebpf.CollectionSpec.LoadAndAssign.
type Openssl330Programs struct {
	SSL_readEntryNestedSyscall    *ebpf.Program `ebpf:"SSL_read_entry_nested_syscall"`
	SSL_readEntryOffset           *ebpf.Program `ebpf:"SSL_read_entry_offset"`
	SSL_readExEntryNestedSyscall  *ebpf.Program `ebpf:"SSL_read_ex_entry_nested_syscall"`
	SSL_readExRetNestedSyscall    *ebpf.Program `ebpf:"SSL_read_ex_ret_nested_syscall"`
	SSL_readRetNestedSyscall      *ebpf.Program `ebpf:"SSL_read_ret_nested_syscall"`
	SSL_readRetOffset             *ebpf.Program `ebpf:"SSL_read_ret_offset"`
	SSL_writeEntryNestedSyscall   *ebpf.Program `ebpf:"SSL_write_entry_nested_syscall"`
	SSL_writeEntryOffset          *ebpf.Program `ebpf:"SSL_write_entry_offset"`
	SSL_writeExEntryNestedSyscall *ebpf.Program `ebpf:"SSL_write_ex_entry_nested_syscall"`
	SSL_writeExRetNestedSyscall   *ebpf.Program `ebpf:"SSL_write_ex_ret_nested_syscall"`
	SSL_writeRetNestedSyscall     *ebpf.Program `ebpf:"SSL_write_ret_nested_syscall"`
	SSL_writeRetOffset            *ebpf.Program `ebpf:"SSL_write_ret_offset"`
}

func (p *Openssl330Programs) Close() error {
	return _Openssl330Close(
		p.SSL_readEntryNestedSyscall,
		p.SSL_readEntryOffset,
		p.SSL_readExEntryNestedSyscall,
		p.SSL_readExRetNestedSyscall,
		p.SSL_readRetNestedSyscall,
		p.SSL_readRetOffset,
		p.SSL_writeEntryNestedSyscall,
		p.SSL_writeEntryOffset,
		p.SSL_writeExEntryNestedSyscall,
		p.SSL_writeExRetNestedSyscall,
		p.SSL_writeRetNestedSyscall,
		p.SSL_writeRetOffset,
	)
}

func _Openssl330Close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed openssl330_x86_bpfel.o
var _Openssl330Bytes []byte
