package tapfreighter

import (
	"bytes"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
)

// BurnLeafProof returns a self-contained copy of a confirmed burn suffix for a
// supply-commitment burn leaf. Universe servers verify that leaf with no prior
// snapshot, so the copy embeds the full proof file of every input the burn
// spends, including the primary input whose provenance a proof file would
// otherwise carry as its prefix.
func BurnLeafProof(suffix *proof.Proof,
	inputFiles map[asset.PrevID]*proof.File) (*proof.Proof, error) {

	if suffix == nil {
		return nil, fmt.Errorf("burn output proof suffix is nil")
	}

	witnesses := suffix.Asset.Witnesses()
	if len(witnesses) == 0 {
		return nil, fmt.Errorf("burn output has no input witnesses")
	}

	seen := make(map[asset.PrevID]struct{}, len(witnesses))
	files := make([]proof.File, 0, len(witnesses))
	for idx := range witnesses {
		prevID := witnesses[idx].PrevID
		if prevID == nil {
			return nil, fmt.Errorf("burn input witness %d has "+
				"no previous ID", idx)
		}
		if _, ok := seen[*prevID]; ok {
			return nil, fmt.Errorf("duplicate burn input %v",
				prevID.OutPoint)
		}
		seen[*prevID] = struct{}{}

		inputFile := inputFiles[*prevID]
		if inputFile == nil {
			return nil, fmt.Errorf("missing proof for burn "+
				"input %v", prevID.OutPoint)
		}
		if inputFile.NumProofs() == 0 {
			return nil, fmt.Errorf("empty proof for burn input %v",
				prevID.OutPoint)
		}

		last, err := inputFile.LastProof()
		if err != nil {
			return nil, fmt.Errorf("invalid proof for burn "+
				"input %v: %w", prevID.OutPoint, err)
		}

		lastID := asset.PrevID{
			OutPoint: last.OutPoint(),
			ID:       last.Asset.ID(),
			ScriptKey: asset.ToSerialized(
				last.Asset.ScriptKey.PubKey,
			),
		}
		if lastID != *prevID {
			return nil, fmt.Errorf("burn input proof mismatch: "+
				"expected %v, got %v", *prevID, lastID)
		}

		files = append(files, *inputFile)
	}

	var buf bytes.Buffer
	if err := suffix.Encode(&buf); err != nil {
		return nil, fmt.Errorf("unable to encode burn proof: %w", err)
	}

	burnProof := &proof.Proof{}
	if err := burnProof.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		return nil, fmt.Errorf("unable to decode burn proof: %w", err)
	}

	burnProof.AdditionalInputs = files

	var encoded bytes.Buffer
	if err := burnProof.Encode(&encoded); err != nil {
		return nil, fmt.Errorf("unable to encode burn leaf: %w", err)
	}
	if encoded.Len() > proof.FileMaxProofSizeBytes {
		return nil, fmt.Errorf("burn leaf proof is too large: "+
			"%d bytes, max is %d", encoded.Len(),
			proof.FileMaxProofSizeBytes)
	}

	return burnProof, nil
}

// cloneProof returns an independent copy of a transition proof.
func cloneProof(p *proof.Proof) (*proof.Proof, error) {
	if p == nil {
		return nil, fmt.Errorf("proof is nil")
	}

	var buf bytes.Buffer
	if err := p.Encode(&buf); err != nil {
		return nil, err
	}

	cloned := &proof.Proof{}
	if err := cloned.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		return nil, err
	}

	return cloned, nil
}

// CloneProofFile returns an independent copy of a proof file.
func CloneProofFile(file *proof.File) (*proof.File, error) {
	return cloneProofFile(file)
}

// cloneProofFile returns an independent copy of a proof file.
func cloneProofFile(file *proof.File) (*proof.File, error) {
	if file == nil {
		return nil, fmt.Errorf("proof file is nil")
	}

	var buf bytes.Buffer
	if err := file.Encode(&buf); err != nil {
		return nil, err
	}

	cloned := &proof.File{}
	if err := cloned.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		return nil, err
	}

	return cloned, nil
}
