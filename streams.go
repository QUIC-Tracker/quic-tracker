package masterthesis

type Stream struct {
	ReadOffset  uint64
	WriteOffset uint64

	ReadData  []byte
	WriteData []byte
}
