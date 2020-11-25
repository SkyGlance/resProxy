package utils

import (
	"log"
	"os"
	"sync"
)

type List struct {
	curSize       int
	mux           sync.Mutex
	container     []interface{}
	containerSize int
}

func (ls *List) Size() int {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	return ls.curSize
}

func (ls *List) At(idx int) (inter interface{}) {
	//	ls.rwMux.RLock()
	//	defer ls.rwMux.RUnlock()
	if idx >= ls.curSize {
		log.Printf("request list size out of range")
		os.Exit(-1)
	}
	inter = ls.container[idx]
	return
}

func (ls *List) Cap() int {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	return len(ls.container)
}

func (ls *List) Clear() {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	for idx := 0; idx < ls.curSize; idx++ {
		ls.container[idx] = nil
	}
	ls.curSize = 0
}

func (ls *List) Swap(newls *List) {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	newls.mux.Lock()
	defer newls.mux.Unlock()
	tmplist := ls.container
	tmpsize := ls.curSize
	ls.container = make([]interface{}, ls.containerSize, ls.containerSize)
	copy(ls.container, newls.container[:newls.curSize])
	ls.curSize = newls.curSize

	newls.container = tmplist
	newls.curSize = tmpsize
}

func (ls *List) Merge(newls *List) {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	newls.mux.Lock()
	defer newls.mux.Unlock()
	if newls.curSize <= 0 {
		return
	}
	if ls.curSize+newls.curSize > len(ls.container) {
		newcontainer := make([]interface{}, ls.curSize+newls.curSize, ls.curSize+newls.curSize)
		copy(newcontainer, ls.container[:ls.curSize])
		copy(newcontainer[ls.curSize:], newls.container[:newls.curSize])
		ls.container = newcontainer
	} else {
		copy(ls.container[ls.curSize:], newls.container[:newls.curSize])
	}
	for idx := 0; idx < newls.curSize; idx++ {
		newls.container[idx] = nil
	}
	ls.curSize += newls.curSize
	newls.curSize = 0
}

func (ls *List) PopFront() (inter interface{}) {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	if ls.curSize <= 0 {
		return nil
	}
	inter = ls.container[0]
	ls.container = ls.container[1:]
	ls.curSize--
	return
}

func (ls *List) PushBack(inter interface{}) {
	ls.mux.Lock()
	defer ls.mux.Unlock()
	if ls.curSize >= len(ls.container) {
		ls.container = append(ls.container, inter)
		ls.curSize++
		return
	}
	ls.container[ls.curSize] = inter
	ls.curSize++
}

func NewList(nmaxcapsize int) *List {
	if nmaxcapsize <= 0 {
		nmaxcapsize = 1
	}
	list := new(List)
	list.containerSize = nmaxcapsize
	list.container = make([]interface{}, nmaxcapsize, nmaxcapsize)
	return list
}
