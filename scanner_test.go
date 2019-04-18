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

import (
	"io/ioutil"
	"testing"
)

func TestChartScanner_ChartPassesScanWhenNoPoliciesAreDefined(t *testing.T) {
	scanner := NewChartScanner(nil)

	chart := readChart(t, "testdata/charts/awesome-chart-0.1.0.tgz")

	err := scanner.Scan(chart)

	if err != nil {
		t.Fatal("chart is expected to pass the scan when no policies are defined")
	}
}

type alwaysPassPolicy struct{}

func (*alwaysPassPolicy) Enforce(chart []byte) error {
	return nil
}

func TestChartScanner_ChartPassesScan(t *testing.T) {
	scanner := NewChartScanner([]Policy{
		&alwaysPassPolicy{},
	})

	chart := readChart(t, "testdata/charts/awesome-chart-0.1.0.tgz")

	err := scanner.Scan(chart)

	if err != nil {
		t.Fatal("chart is expected to pass the scan")
	}
}

type alwaysFailPolicy struct{}

func (*alwaysFailPolicy) Enforce(chart []byte) error {
	return &policyViolationError{
		violation: "some violation",
		policy:    "always-fail",
	}
}

func TestChartScanner_ChartFailsScan(t *testing.T) {
	scanner := NewChartScanner([]Policy{
		&alwaysFailPolicy{},
	})

	chart := readChart(t, "testdata/charts/awesome-chart-0.1.0.tgz")

	err := scanner.Scan(chart)

	if err == nil {
		t.Fatal("chart is expected to fail the scan")
	}

	verr, ok := err.(PolicyViolationError)
	if !ok {
		t.Fatalf("violation error is expected to be of type PolicyViolationError, received: %T", err)
	}

	if verr.Violation() != "some violation" {
		t.Fatalf("unexpected violation: %s", verr.Violation())
	}

	if verr.Policy() != "always-fail" {
		t.Fatalf("unexpected policy: %s", verr.Policy())
	}
}

func readChart(t *testing.T, chartPath string) []byte {
	t.Helper()

	chart, err := ioutil.ReadFile(chartPath)
	if err != nil {
		t.Fatal("failed to read chart")
	}

	return chart
}
