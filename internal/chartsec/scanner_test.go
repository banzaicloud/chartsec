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
	scanner := NewChartScanner()

	chart := openChart(t, "../../testdata/archives/large_archive.tgz")

	err := scanner.Scan(chart)

	if err == nil {
		t.Fatal("chart is expected to fail the security scan")
	}

	if got, want := err.Error(), "too large chart archive"; got != want {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestChartScanner_LargeData(t *testing.T) {
	scanner := NewChartScanner()

	chart := openChart(t, "../../testdata/archives/large_data.tgz")

	err := scanner.Scan(chart)

	if err == nil {
		t.Fatal("chart is expected to fail the security scan")
	}

	if got, want := err.Error(), "too large chart"; got != want {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestChartScanner_MaliciousContent(t *testing.T) {
	scanner := NewChartScanner()

	tests := []string{"malicious-chart", "other-malicious-chart"}

	for _, test := range tests {
		test := test

		t.Run(test, func(t *testing.T) {
			chart := openChart(t, fmt.Sprintf("../../testdata/charts/%s-0.1.0.tgz", test))

			err := scanner.Scan(chart)

			if err == nil {
				t.Fatal("chart is expected to fail the security scan")
			}

			if got, want := err.Error(), "chart contains malicious content"; got != want {
				t.Errorf("unexpected error: %s", got)
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
