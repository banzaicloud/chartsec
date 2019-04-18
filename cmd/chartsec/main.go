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

package main

import (
	"fmt"
	"os"

	"github.com/banzaicloud/chartsec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("chartsec requires an argument")
		os.Exit(1)
	}

	if os.Args[1] == "-h" {
		fmt.Println("Usage:\nchartsec path/to/file")
		os.Exit(0)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("failed to open chart file:", err)
		os.Exit(1)
	}

	scanner := chartsec.NewDefaultChartScanner()

	err = scanner.Scan(file)
	if err != nil {
		fmt.Println("chart scan failed:", err)
		os.Exit(1)
	}
}
