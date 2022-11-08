package server

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"strings"
)

type ProveRequest struct {
	Payload []uint `json:"payload,omitempty"`
	Mask    []uint `json:"mask,omitempty"`
	Tblock  uint8  `json:"tblock,omitempty"`
}

func toBits(byteArray []byte) []uint {
	var bits []uint
	for _, v := range byteArray {
		for i := 0; i < 8; i++ {
			// We're extracting a single bit per uint.
			// Extract a bit from v: int(v)&(128>>i)
			// And move it into that uint's least significant position: >>(7-i)
			bits = append(bits, (uint(v)&(128>>i))>>(7-i))
		}
	}
	return bits
}

func fromBits(bits []uint) uint {
	var result uint
	for i := 0; i < len(bits); i++ {
		// We're inserting bits into a uint
		// Shift the new bit into position: (bits[len(bits)-1-i] << i)
		// And insert it: uint(result) |
		result = uint(result) | (bits[len(bits)-1-i] << i)
	}
	return result
}

// https://datatracker.ietf.org/doc/html/rfc4634#section-4.1
func padMessage(bits []uint) []uint {
	var L uint64 = uint64(len(bits))
	var K uint64 = (512 + 448 - (L%512 + 1)) % 512

	bits = append(bits, 1)
	if K > 0 {
		for i := uint64(0); i < K; i++ {
			bits = append(bits, 0)
		}
	}
	LBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(LBytes, L)
	bits = append(bits, toBits(LBytes)...)

	return bits
}

func genJwtMask(headerLen uint64, payload string, masklen int, fields []string) []uint {
	var mask []uint
	for i := 0; i < masklen; i++ {
		mask = append(mask, 0)
	}

	for _, field := range fields {
		fieldKey := "\"" + field + "\":"

		fieldKeyStart := strings.Index(payload, fieldKey)
		if fieldKeyStart == -1 {
			log.Panic("fieldKey not found")
		}
		trimmedInput := payload[fieldKeyStart+len(fieldKey):]
		fieldValueEnd := strings.Index(trimmedInput, ",") // TODO: can any value contain a comma?
		if fieldValueEnd == -1 {
			log.Panic("comma after fieldKey not found")
		}
		trimmedLen := len(payload) - len(trimmedInput)
		fieldEnd := fieldValueEnd + trimmedLen

		lead := base64.StdEncoding.EncodeToString([]byte(payload[0:fieldKeyStart]))
		lead = strings.TrimSuffix(lead, "=")
		lead = strings.TrimSuffix(lead, "=")
		target := base64.StdEncoding.EncodeToString([]byte(payload[fieldKeyStart:fieldEnd]))
		target = strings.TrimSuffix(target, "=")
		target = strings.TrimSuffix(target, "=")

		start := uint64(math.Floor(float64(len(lead))/4.0)) * 4
		end := uint64(math.Ceil((float64(len(lead+target)-1) / 4)) * 4)

		if end >= uint64(masklen) {
			end = uint64(masklen - 1)
		} else {
			end = end - 1
		}

		for i := headerLen + 1 + start; i <= headerLen+1+end; i++ {
			mask[i] = 1
		}
	}

	return mask
}

func genSha256Inputs(input string, nCount uint, nWidth uint) ([][]uint, uint8) {
	inputBytes := []byte(input)
	bits := toBits(inputBytes)
	bits = padMessage(bits)

	chunk_size := nWidth
	chunks := uint(len(bits)) / nWidth // TODO: original snark-jwt code used math.ceil here, not sure if we need it
	var segments [][]uint
	for i := uint(0); i < chunks; i++ {
		chunkStart := i * chunk_size
		chunkEnd := chunk_size + i*chunk_size
		segments = append(segments, bits[chunkStart:chunkEnd])
	}

	var tBlock uint8 = uint8(uint(len(segments)) / (512 / nWidth))

	// The circuit requires us to set up a fixed length, while an individual proof's segments might be smaller
	if uint(len(segments)) < nCount {
		var empty []uint // TODO: there must be a shorthand for creating a zero-initialized array
		for i := uint(0); i < nWidth; i++ {
			empty = append(empty, 0)
		}
		for i := uint(0); i < nCount-uint(len(segments)); i++ {
			segments = append(segments, empty)
		}
	}

	if uint(len(segments)) > nCount {
		fmt.Println("Padded message exceeds maximum blocks supported by circuit, segments.length:", len(segments), " - nCount: ", nCount)
	}

	return segments, tBlock
}

func genJwtProofInputs(input string) ProveRequest {
	inputParts := strings.Split(input, ".")
	// TODO: determine padding in an automated way
	decodedHeader, err := base64.StdEncoding.DecodeString(inputParts[0] + "==")
	if err != nil {
		fmt.Printf("An Error Occured %v\n", err)
		return ProveRequest{}
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(inputParts[1] + "=")
	if err != nil {
		fmt.Printf("An Error Occured %v\n", err)
		return ProveRequest{}
	}
	decoded := append(decodedHeader, decodedPayload...)

	if err != nil {
		fmt.Printf("An Error Occured %v\n", err)
		return ProveRequest{}
	}
	fields := []string{"iss", "aud", "exp", "iat", "nonce", "at_hash", "c_hash", "email_verified"}

	var nCount uint = 704
	var nWidth uint = 16

	payloadBits, tBlock := genSha256Inputs(string(decoded), nCount, nWidth)
	var newPayload []uint
	for i := 0; i < len(payloadBits); i++ {
		newPayload = append(newPayload, fromBits(payloadBits[i]))
	}
	var proveRequest ProveRequest
	proveRequest.Tblock = tBlock
	proveRequest.Payload = newPayload
	proveRequest.Mask = genJwtMask(uint64(len(inputParts[0])), string(decodedPayload), len(input), fields)
	for i := 0; uint(i) < nCount-uint(len(decoded)); i++ {
		proveRequest.Mask = append(proveRequest.Mask, 0)
	}

	return proveRequest
}
