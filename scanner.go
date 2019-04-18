// Copyright © 2019 Banzai Cloud
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

package chartsec

// ChartScanner scans a Helm chart archive for security issues.
type ChartScanner struct {
	policies []Policy
}

// NewChartScanner returns a new ChartScanner instance.
func NewChartScanner(policies []Policy) *ChartScanner {
	return &ChartScanner{
		policies: policies,
	}
}

// Scan runs the security scans on a Helm chart archive.
func (s *ChartScanner) Scan(chart []byte) error {
	for _, policy := range s.policies {
		err := policy.Enforce(chart)
		if err != nil {
			return err
		}
	}

	return nil
}
