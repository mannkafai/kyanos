package buffer_test

import (
	"fmt"
	"kyanos/agent/buffer"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamBuffer(t *testing.T) {
	sb := buffer.New(10)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
}

func TestStreamBuffer2(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(10, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 2, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
	b1 := buffers[1]
	assert.Equal(t, b1.Buffer(), data2)
}

func TestStreamBuffer3(t *testing.T) {
	sb := buffer.New(1000)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(10, data2, 3)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 2, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
	b1 := buffers[1]
	assert.Equal(t, b1.Buffer(), data2)
}

func TestStreamBufferFuseAsRight(t *testing.T) {
	sb := buffer.New(1000)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(6, data2, 3)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(data, data2...))
}

func TestStreamBufferFuseAsLeft(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(6, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(data, data2...))
}

func TestStreamBufferFuseAsMiddle(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4} // [1,5]
	sb.Add(1, data, 2)
	data3 := []byte{11, 12, 16, 71, 18} // [11,15]
	sb.Add(11, data3, 3)
	data2 := []byte{4, 5, 6, 7, 8} // [6,10]
	sb.Add(6, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(append(data, data2...), data3...))
}

func TestStreamBufferCompleteOverlapAsLeft(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(1, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
}

func TestStreamBufferPartialOverlapAsLeft(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(3, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(data, data2[3:]...))
}

func TestStreamBufferCompleteOverlapAsRight(t *testing.T) {
	sb := buffer.New(1000)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(1, data2, 3)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data2)
}

func TestStreamBufferPartialOverlapAsMiddle(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4} // [1,5]
	sb.Add(1, data, 2)
	data3 := []byte{11, 12, 16, 71, 18} // [11,15]
	sb.Add(11, data3, 3)
	data2 := []byte{3, 4, 5, 6, 7, 80, 1} // [6,10]
	sb.Add(5, data2, 3)
	fmt.Println(data2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(append(data, data2[1:6]...), data3...))
}
