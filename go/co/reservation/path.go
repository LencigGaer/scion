// Copyright 2020 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reservation

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
)

// PathStep encompasses one-hop metadata in COLIBRI
type PathStep struct {
	Ingress uint16
	Egress  uint16
	IA      addr.IA
}

func (s PathStep) Equal(o PathStep) bool {
	return s.Ingress == o.Ingress && s.Egress == o.Egress && s.IA.Equal(o.IA)
}

const PathStepLen = 2 + 2 + 8

func ColPathToRaw(p *colpath.ColibriPathMinimal) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	return (*p).ToBytes()
}

func ColPathFromRaw(raw []byte) (*colpath.ColibriPathMinimal, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	p := &colpath.ColibriPathMinimal{}
	return p, p.FromBytes(raw)
}

type PathSteps []PathStep

func (p PathSteps) SrcIA() addr.IA {
	return p[0].IA
}

func (p PathSteps) DstIA() addr.IA {
	return p[len(p)-1].IA
}

// Size returns PathSteps size in bytes
func (p PathSteps) Size() int {
	return 2 + len(p)*PathStepLen
}

func (p PathSteps) Serialize(buff []byte) {
	binary.BigEndian.PutUint16(buff, uint16(len(p)))
	buff = buff[2:]
	for _, step := range p {
		binary.BigEndian.PutUint16(buff, step.Ingress)
		binary.BigEndian.PutUint16(buff[2:], step.Egress)
		binary.BigEndian.PutUint64(buff[4:], uint64(step.IA))
		buff = buff[12:]
	}
}

func (p PathSteps) ToRaw() []byte {
	buff := make([]byte, p.Size())
	p.Serialize(buff)
	return buff
}

func PathStepsFromRaw(raw []byte) PathSteps {
	stepCount := int(binary.BigEndian.Uint16(raw))
	raw = raw[2:]
	steps := make([]PathStep, stepCount)
	for i := 0; i < stepCount; i++ {
		steps[i].Ingress = binary.BigEndian.Uint16(raw)
		steps[i].Egress = binary.BigEndian.Uint16(raw[2:])
		steps[i].IA = addr.IA(binary.BigEndian.Uint64(raw[4:]))
		raw = raw[12:]
	}
	return steps
}

func (p PathSteps) Copy() PathSteps {
	return append(p[:0:0], p...)
}

func (p PathSteps) Reverse() PathSteps {
	rev := make([]PathStep, len(p))
	for i, s := range p {
		s.Ingress, s.Egress = s.Egress, s.Ingress
		rev[len(rev)-i-1] = s
	}
	return rev
}

// Interfaces return a snet.PathInterfaces leaving out the leading and trailing
// virtual interfaces.
func (p PathSteps) Interfaces() []snet.PathInterface {
	if p == nil {
		return []snet.PathInterface{}
	}
	ifaces := make([]snet.PathInterface, len(p)*2) // it has two too many
	for i := 0; i < len(p); i++ {
		ifaces[i*2].ID = common.IFIDType(p[i].Ingress)
		ifaces[i*2].IA = p[i].IA
		ifaces[i*2+1].ID = common.IFIDType(p[i].Egress)
		ifaces[i*2+1].IA = p[i].IA
	}
	//
	return ifaces[1 : len(ifaces)-1]
}

func (p PathSteps) String() string {
	strs := make([]string, len(p))
	for i, s := range p {
		if s.IA.IsZero() {
			strs[i] = fmt.Sprintf("%d,%d", s.Ingress, s.Egress)
		} else {
			strs[i] = fmt.Sprintf("%d,%s,%d", s.Ingress, s.IA, s.Egress)
		}
	}
	return strings.Join(strs, " > ")
}

// ValidateEquivalent checks that these steps are compatible with the path.
// Compatible means the ingress/egress interface of the current step is the same
// as those of the transport path.
// TODO(juagargi) support colibri EER paths
func (s PathSteps) ValidateEquivalent(path *colpath.ColibriPathMinimal, atStep int) error {
	if path == nil {
		return nil
	}
	infF := path.GetInfoField()
	if !infF.S {
		panic("colibri EER paths are not yet supported")
	}
	hf := path.GetCurrentHopField()
	in, eg := hf.IngressId, hf.EgressId
	// if using a SegR in a stitching point, ingress or egress could be 0, depending on
	// whether the first segment or the second is being validated
	if infF.S {
		if infF.CurrHF == 0 { // second segment, ignore ingress (it is us)
			in = s[atStep].Ingress
		} else if infF.CurrHF == infF.HFCount-1 { // first segment, ignore egress (it's us)
			eg = s[atStep].Egress
		}
	}
	if in != s[atStep].Ingress || eg != s[atStep].Egress {
		return serrors.New("steps and path are not equivalent",
			"path_type", path.Type().String(),
			"path", fmt.Sprintf("[%d,%d]", in, eg),
			"steps", fmt.Sprintf("[%d,%d]", s[atStep].Ingress, s[atStep].Egress))
	}

	return nil
}

func (s PathSteps) Equal(o PathSteps) bool {
	if len(s) != len(o) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !s[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

func StepsFromSnet(p snet.Path) (PathSteps, error) {
	if p == nil {
		return nil, nil
	}
	steps, err := StepsFromInterfaces(p.Metadata().Interfaces)
	if err != nil {
		return nil, err
	}

	return steps, err
}

func StepsFromInterfaces(ifaces []snet.PathInterface) (PathSteps, error) {
	if len(ifaces)%2 != 0 {
		return nil, serrors.New("wrong number of interfaces, not even", "ifaces", ifaces)
	}
	if len(ifaces) == 0 {
		return PathSteps{}, nil
	}
	steps := make([]PathStep, len(ifaces)/2+1)

	for i := 0; i < len(steps)-1; i++ {
		steps[i].Egress = uint16(ifaces[i*2].ID)
		steps[i].IA = ifaces[i*2].IA
		steps[i+1].Ingress = uint16(ifaces[i*2+1].ID)
	}
	steps[len(steps)-1].IA = ifaces[len(ifaces)-1].IA
	return steps, nil
}

func InEgFromColibriPath(path *colpath.ColibriPathMinimal) (uint16, uint16) {
	return path.CurrHopField.IngressId, path.CurrHopField.EgressId
}
