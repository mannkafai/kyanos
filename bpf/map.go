package bpf

import (
	"reflect"

	"github.com/cilium/ebpf"
)

func GetMap(mapName string) *ebpf.Map {
	oldObjs, isOld := Objs.(*AgentOldObjects)
	if isOld {
		maps := oldObjs.AgentOldMaps
		v := reflect.ValueOf(maps)
		f := v.FieldByName(mapName).Interface()
		return f.(*ebpf.Map)
	} else {
		newobjs := Objs.(*AgentObjects)
		maps := newobjs.AgentMaps
		v := reflect.ValueOf(maps)
		f := v.FieldByName(mapName).Interface()
		return f.(*ebpf.Map)
	}
}