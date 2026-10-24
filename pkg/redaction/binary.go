package redaction

import "encoding/binary"

// Compiled formats keep offsets and detector context stable when a sensitive
// field becomes REDACTED followed by spaces inside its original extent.
// Check structural headers, rather than treating arbitrary binary-looking text
// or a Java class / fat Mach-O magic as a compiled source file.
func compiledBinary(input []byte) bool {
	return elfBinary(input) || peBinary(input) || machoBinary(input)
}

func elfBinary(input []byte) bool {
	if len(input) < 52 || string(input[:4]) != "\x7fELF" || input[6] != 1 {
		return false
	}
	var order binary.ByteOrder
	switch input[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return false
	}
	if kind := order.Uint16(input[16:18]); kind < 1 || kind > 4 || order.Uint32(input[20:24]) != 1 {
		return false
	}
	var header, programSize, sectionSize uint64
	var programOffset, sectionOffset uint64
	var programCount, sectionCount uint16
	switch input[4] {
	case 1:
		header, programSize, sectionSize = 52, 32, 40
		if order.Uint16(input[40:42]) != uint16(header) {
			return false
		}
		programOffset, sectionOffset = uint64(order.Uint32(input[28:32])), uint64(order.Uint32(input[32:36]))
		programCount, sectionCount = order.Uint16(input[44:46]), order.Uint16(input[48:50])
		if programCount != 0 && order.Uint16(input[42:44]) != uint16(programSize) || sectionCount != 0 && order.Uint16(input[46:48]) != uint16(sectionSize) {
			return false
		}
	case 2:
		header, programSize, sectionSize = 64, 56, 64
		if len(input) < int(header) || order.Uint16(input[52:54]) != uint16(header) {
			return false
		}
		programOffset, sectionOffset = order.Uint64(input[32:40]), order.Uint64(input[40:48])
		programCount, sectionCount = order.Uint16(input[56:58]), order.Uint16(input[60:62])
		if programCount != 0 && order.Uint16(input[54:56]) != uint16(programSize) || sectionCount != 0 && order.Uint16(input[58:60]) != uint16(sectionSize) {
			return false
		}
	default:
		return false
	}
	return (programCount != 0 || sectionCount != 0) &&
		binaryTableWithin(input, sectionOffset, uint64(sectionCount), sectionSize, header) &&
		binaryTableWithin(input, programOffset, uint64(programCount), programSize, header)
}

func binaryTableWithin(input []byte, offset, count, size, minimum uint64) bool {
	if count == 0 {
		return offset == 0
	}
	return offset >= minimum && offset <= uint64(len(input)) && count <= (uint64(len(input))-offset)/size
}

func peBinary(input []byte) bool {
	if len(input) < 64 || string(input[:2]) != "MZ" {
		return false
	}
	offset := uint64(binary.LittleEndian.Uint32(input[60:64]))
	if offset < 64 || offset+24 > uint64(len(input)) || string(input[int(offset):int(offset)+4]) != "PE\x00\x00" {
		return false
	}
	coff := input[int(offset)+4 : int(offset)+24]
	sections, optionalSize := binary.LittleEndian.Uint16(coff[2:4]), binary.LittleEndian.Uint16(coff[16:18])
	optionalStart := offset + 24
	if sections == 0 || sections > 96 || optionalSize < 2 || optionalStart+uint64(optionalSize) > uint64(len(input)) || binary.LittleEndian.Uint16(coff[18:20])&2 == 0 {
		return false
	}
	magic := binary.LittleEndian.Uint16(input[int(optionalStart) : int(optionalStart)+2])
	if magic != 0x10b && magic != 0x20b || magic == 0x10b && optionalSize < 96 || magic == 0x20b && optionalSize < 112 {
		return false
	}
	table := optionalStart + uint64(optionalSize)
	if !binaryTableWithin(input, table, uint64(sections), 40, optionalStart) {
		return false
	}
	for i := uint64(0); i < uint64(sections); i++ {
		header := input[int(table+i*40):int(table+(i+1)*40)]
		size, start := uint64(binary.LittleEndian.Uint32(header[16:20])), uint64(binary.LittleEndian.Uint32(header[20:24]))
		if start > uint64(len(input)) || size > uint64(len(input))-start {
			return false
		}
	}
	return true
}

func machoBinary(input []byte) bool {
	if len(input) < 28 {
		return false
	}
	var order binary.ByteOrder
	headerSize := 28
	switch binary.BigEndian.Uint32(input[:4]) {
	case 0xfeedface:
		order = binary.BigEndian
	case 0xcefaedfe:
		order = binary.LittleEndian
	case 0xfeedfacf:
		order, headerSize = binary.BigEndian, 32
	case 0xcffaedfe:
		order, headerSize = binary.LittleEndian, 32
	default:
		return false
	}
	if len(input) < headerSize || order.Uint32(input[4:8]) == 0 {
		return false
	}
	kind, commands, commandBytes := order.Uint32(input[12:16]), order.Uint32(input[16:20]), order.Uint32(input[20:24])
	if kind < 1 || kind > 12 || commands == 0 || commands > 65536 || commandBytes > uint32(len(input)-headerSize) || commands > commandBytes/8 {
		return false
	}
	cursor, end := uint64(headerSize), uint64(headerSize)+uint64(commandBytes)
	for range commands {
		if cursor+8 > end {
			return false
		}
		size := uint64(order.Uint32(input[int(cursor)+4 : int(cursor)+8]))
		if size < 8 || size%4 != 0 || size > end-cursor {
			return false
		}
		cursor += size
	}
	return cursor == end
}
