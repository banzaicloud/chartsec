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
	"fmt"
	"io"
	"os"
	"testing"
)

func TestChartScanner_ValidChart(t *testing.T) {
	scanner := NewChartScanner()

	chart := openChart(t, "../../testdata/charts/awesome-chart-0.1.0.tgz")

	err := scanner.Scan(chart)

	if err != nil {
		t.Fatal("chart is expected to pass the security scan:", err)
	}
}

func TestChartScanner_LargeArchive(t *testing.T) {
	err := testViolation(t, "../../testdata/archives/large_archive.tgz")

	if got, want := err.Error(), "chart is too large"; got != want {
		t.Errorf("unexpected error: %s", got)
	}

	if got, want := err.Policy(), compressedArchiveSizePolicy; got != want {
		t.Errorf("unexpected policy: %s", got)
	}
}

func TestChartScanner_LargeData(t *testing.T) {
	err := testViolation(t, "../../testdata/archives/large_data.tgz")

	if got, want := err.Error(), "chart is too large"; got != want {
		t.Errorf("unexpected error: %s", got)
	}

	if got, want := err.Policy(), uncompressedArchiveSizePolicy; got != want {
		t.Errorf("unexpected policy: %s", got)
	}
}

func TestChartScanner_MaliciousContent(t *testing.T) {
	tests := []string{"malicious-content-1", "malicious-content-1"}

	for _, test := range tests {
		test := test

		t.Run(test, func(t *testing.T) {
			err := testViolation(t, fmt.Sprintf("../../testdata/archives/%s.tgz", test))

			if got, want := err.Error(), "chart contains malicious content in file: malicious-content-1/README.md"; got != want {
				t.Errorf("unexpected error: %s", got)
			}

			if got, want := err.Policy(), maliciousContentPolicy; got != want {
				t.Errorf("unexpected policy: %s", got)
			}
		})
	}
}

func openChart(t *testing.T, chartPath string) io.Reader {
	t.Helper()

	chart, err := os.Open(chartPath)
	if err != nil {
		t.Fatal("failed to open chart:", err)
	}

	return chart
}

func testViolation(t *testing.T, chartPath string) PolicyViolationError {
	scanner := NewChartScanner()

	chart := openChart(t, chartPath)

	err := scanner.Scan(chart)

	if err == nil {
		t.Fatal("chart is expected to fail the security scan")
	}

	verr, ok := err.(PolicyViolationError)
	if !ok {
		t.Fatalf("error is expected to be of type PolicyViolationError, received: %T", err)
	}

	return verr
}
