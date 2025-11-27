package rocky

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractVersionModuleFromNevra(t *testing.T) {
	tests := []struct {
		nevra         string
		moduleName    string
		moduleVersion string
	}{
		{nevra: "valkey-0:8.0.6-2.el10_1.ppc64le.rpm", moduleName: "valkey", moduleVersion: "8.0.6-2.el10_1"},
		{nevra: "kernel-0:6.12.0-124.8.1.el10_1.aarch64.rpm", moduleName: "kernel", moduleVersion: "6.12.0-124.8.1.el10_1"},
		{nevra: "kernel-64k-debug-core-0:6.12.0-124.8.1.el10_1.aarch64.rpm", moduleName: "kernel-64k-debug-core", moduleVersion: "6.12.0-124.8.1.el10_1"},
		{nevra: "kernel-abi-stablelists-0:6.12.0-124.8.1.el10_1.noarch.rpm", moduleName: "kernel-abi-stablelists", moduleVersion: "6.12.0-124.8.1.el10_1"},
	}
	for _, test := range tests {
		moduleName, moduleVersion := extractVersionModuleFromNevra(test.nevra)
		require.Equal(t, test.moduleName, moduleName)
		require.Equal(t, test.moduleVersion, moduleVersion)
	}
}
