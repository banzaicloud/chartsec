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

// PolicyViolationError contains the details for a policy violation.
type PolicyViolationError interface {
	error

	// Policy returns the name of the policy.
	Policy() string

	// Context returns the context of the violation.
	Context() string
}

// policyViolationError contains the details for a policy violation.
type policyViolationError struct {
	violation string
	policy    string
	context   string
}

// Policy returns the name of the policy.
func (e *policyViolationError) Policy() string {
	return e.policy
}

// Context returns the context of the violation.
func (e *policyViolationError) Context() string {
	return e.context
}

// Error implements the builtin error interface.
func (e *policyViolationError) Error() string {
	return e.violation
}
