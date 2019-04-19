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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/pkg/errors"
)

const (
	maxArchiveSize = 10 * 1024 * 1024 // 10 MB
	maxDataSize    = 10 * 1024 * 1024 // 10 MB
)

const (
	compressedArchiveSizePolicy   = "compressed-archive-size"
	uncompressedArchiveSizePolicy = "uncompressed-archive-size"
	maliciousContentPolicy        = "maliciousContent"
)

// ChartScanner scans a Helm chart archive for security issues.
type ChartScanner struct{}

// NewChartScanner returns a new ChartScanner instance.
func NewChartScanner() *ChartScanner {
	return &ChartScanner{}
}

// Scan runs the security scans on a Helm chart archive.
func (s *ChartScanner) Scan(r io.Reader) error {
	gzbuf := new(bytes.Buffer)

	// Make sure the archive does not exceed the maximum size
	readBytes, err := io.CopyN(gzbuf, r, maxArchiveSize)
	if err != nil && err != io.EOF {
		return errors.Wrap(err, "failed to read chart archive")
	}

	if err != io.EOF && readBytes == maxArchiveSize {
		return &policyViolationError{
			violation: "too large chart archive",
			policy:    compressedArchiveSizePolicy,
		}
	}

	gzr, err := gzip.NewReader(gzbuf)
	if err != nil {
		return errors.Wrap(err, "failed to open chart gzip archive")
	}

	tarbuf := new(bytes.Buffer)

	// Make sure the uncompressed archive does not exceed the maximum size
	readBytes, err = io.CopyN(tarbuf, gzr, maxDataSize)
	if err != nil && err != io.EOF {
		return errors.Wrap(err, "failed to decompress chart archive")
	}

	if err != io.EOF && readBytes == maxDataSize {
		return &policyViolationError{
			violation: "too large chart",
			policy:    uncompressedArchiveSizePolicy,
		}
	}

	_ = gzr.Close()

	tr := tar.NewReader(tarbuf)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return errors.Wrap(err, "failed to extract chart archive")
		}

		fileName := header.Name

		if strings.EqualFold(filepath.Ext(fileName), ".md") {
			content, err := ioutil.ReadAll(tr)
			if err != nil {
				return errors.Wrapf(err, "failed to extract file %q from chart archive", fileName)
			}

			sanitizedContent := bluemonday.UGCPolicy().SanitizeBytes(content)

			if !bytes.Equal(content, sanitizedContent) {
				return &policyViolationError{
					violation: "chart contains malicious content",
					policy:    maliciousContentPolicy,
				}
			}
		}
	}

	return nil
}
