//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package database defines the Clair's models and a common interface for database implementations.
package updater

import (
	"github.com/vul-dbgen/common"
)

// Datastore is the interface that describes a database backend implementation.
type Datastore interface {
	InsertVulnerabilities(vulnerabilities []*common.Vulnerability, appVuls []*common.AppModuleVul, rawFiles []*common.RawFile) error

	Close()
}
