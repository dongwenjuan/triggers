*
Copyright 2019 The Tekton Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gerrit

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"json"
	"net/http"

	gh "github.com/google/go-github/v31/github"
	"https://github.com/sokolovstas/gerrit-ssh"
	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1alpha1"
	"github.com/tektoncd/triggers/pkg/interceptors"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")

type Interceptor struct {
	KubeClientSet          kubernetes.Interface
	Logger                 *zap.SugaredLogger
	Gerrit                 *triggersv1.GerritInterceptor
	EventListenerNamespace string
}

func NewInterceptor(geh *triggersv1.GerritInterceptor, k kubernetes.Interface, ns string, l *zap.SugaredLogger) interceptors.Interceptor {
	return &Interceptor{
		Logger:                 l,
		Gerrit:                 geh,
		KubeClientSet:          k,
		EventListenerNamespace: ns,
	}
}

func (w *Interceptor) ExecuteTrigger(request *http.Request) (*http.Response, error) {
	payload := []byte{}
	var err error
	if v := request.Header.Get("Content-Type"); v == "application/x-www-form-urlencoded" {
		return nil, ErrInvalidContentType
	}

	if request.Body != nil {
		defer request.Body.Close()
		payload, err = ioutil.ReadAll(request.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Next see if the event type is in the allow-list
	if w.Gerrit.EventType != nil || w.Gerrit.Project != nil {
	    event := gerritssh.StreamEvent{}
	    err := json.Unmarshal(payload, &event)
	    if err != nil {
	        return nil, fmt.Errorf("failed to Unmarshal request body: %w", err)
	    }

        if event.Type != w.Gerrit.EventType || event.Project != w.Gerrit.Project {
            return nil, fmt.Errorf("event type %s or project %s is not allowed", event.Type, event.Project)
        }
	}

	return &http.Response{
		Header: request.Header,
		Body:   ioutil.NopCloser(bytes.NewBuffer(payload)),
	}, nil
}
