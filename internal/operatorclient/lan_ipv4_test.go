package operatorclient

import (
	"github.com/teddashh/AI-Intune/internal/operator"
	"testing"
)

func TestLANIPv4ClientRejectsUnsafeOrIncoherentDisclosure(t *testing.T) {
	for _, p := range []operator.MachineLANIPv4{
		{Items: []string{}}, {Total: 1, Items: []string{"10.1.2.3"}},
		{Total: 20, Invalid: 3, Truncated: true, Items: []string{"192.168.1.2"}},
	} {
		if err := validateMachineLANIPv4(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []operator.MachineLANIPv4{
		{}, {Total: 1, Items: []string{"secret"}}, {Total: 1, Items: []string{"100.64.0.3"}},
		{Total: 2, Items: []string{"10.1.2.3", "10.1.2.3"}},
		{Total: 0, Items: []string{"10.1.2.3"}}, {Total: 2, Items: []string{"10.1.2.3"}},
	} {
		if err := validateMachineLANIPv4(p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}
