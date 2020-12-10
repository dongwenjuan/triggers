/*
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

package github

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	triggersv1 "github.com/dongwenjuan/triggers/pkg/apis/triggers/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/logging"
	rtesting "knative.dev/pkg/reconciler/testing"
)

func TestInterceptor_ExecuteTrigger_Signature(t *testing.T) {
	type args struct {
		payload   io.ReadCloser
		secret    *corev1.Secret
		signature string
		eventType string
	}
	tests := []struct {
		name    string
		GitHub  *triggersv1.GitHubInterceptor
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:   "no secret",
			GitHub: &triggersv1.GitHubInterceptor{},
			args: args{
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
				signature: "foo",
			},
			want:    []byte("somepayload"),
			wantErr: false,
		},
		{
			name: "invalid header for secret",
			GitHub: &triggersv1.GitHubInterceptor{
				SecretRef: &triggersv1.SecretRef{
					SecretName: "mysecret",
					SecretKey:  "token",
				},
			},
			args: args{
				signature: "foo",
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mysecret",
					},
					Data: map[string][]byte{
						"token": []byte("secrettoken"),
					},
				},
				payload: ioutil.NopCloser(bytes.NewBufferString("somepayload")),
			},
			wantErr: true,
		},
		{
			name: "valid header for secret",
			GitHub: &triggersv1.GitHubInterceptor{
				SecretRef: &triggersv1.SecretRef{
					SecretName: "mysecret",
					SecretKey:  "token",
				},
			},
			args: args{
				// This was generated by using SHA1 and hmac from go stdlib on secret and payload.
				// https://play.golang.org/p/otp1o_cJTd7 for a sample.
				signature: "sha1=38e005ef7dd3faee13204505532011257023654e",
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mysecret",
					},
					Data: map[string][]byte{
						"token": []byte("secret"),
					},
				},
				payload: ioutil.NopCloser(bytes.NewBufferString("somepayload")),
			},
			wantErr: false,
			want:    []byte("somepayload"),
		},
		{
			name: "no secret, matching event",
			GitHub: &triggersv1.GitHubInterceptor{
				EventTypes: []string{"MY_EVENT", "YOUR_EVENT"},
			},
			args: args{
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
				eventType: "YOUR_EVENT",
			},
			wantErr: false,
			want:    []byte("somepayload"),
		},
		{
			name: "no secret, failing event",
			GitHub: &triggersv1.GitHubInterceptor{
				EventTypes: []string{"MY_EVENT", "YOUR_EVENT"},
			},
			args: args{
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
				eventType: "OTHER_EVENT",
			},
			wantErr: true,
		},
		{
			name: "valid header for secret and matching event",
			GitHub: &triggersv1.GitHubInterceptor{
				SecretRef: &triggersv1.SecretRef{
					SecretName: "mysecret",
					SecretKey:  "token",
				},
				EventTypes: []string{"MY_EVENT", "YOUR_EVENT"},
			},
			args: args{
				// This was generated by using SHA1 and hmac from go stdlib on secret and payload.
				// https://play.golang.org/p/otp1o_cJTd7 for a sample.
				signature: "sha1=38e005ef7dd3faee13204505532011257023654e",
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mysecret",
					},
					Data: map[string][]byte{
						"token": []byte("secret"),
					},
				},
				eventType: "MY_EVENT",
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
			},
			wantErr: false,
			want:    []byte("somepayload"),
		},
		{
			name: "valid header for secret, failing event",
			GitHub: &triggersv1.GitHubInterceptor{
				SecretRef: &triggersv1.SecretRef{
					SecretName: "mysecret",
					SecretKey:  "token",
				},
				EventTypes: []string{"MY_EVENT", "YOUR_EVENT"},
			},
			args: args{
				// This was generated by using SHA1 and hmac from go stdlib on secret and payload.
				// https://play.golang.org/p/otp1o_cJTd7 for a sample.
				signature: "sha1=38e005ef7dd3faee13204505532011257023654e",
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mysecret",
					},
					Data: map[string][]byte{
						"token": []byte("secret"),
					},
				},
				eventType: "OTHER_EVENT",
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
			},
			wantErr: true,
		},
		{
			name: "invalid header for secret, matching event",
			GitHub: &triggersv1.GitHubInterceptor{
				SecretRef: &triggersv1.SecretRef{
					SecretName: "mysecret",
					SecretKey:  "token",
				},
				EventTypes: []string{"MY_EVENT", "YOUR_EVENT"},
			},
			args: args{
				signature: "foo",
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mysecret",
					},
					Data: map[string][]byte{
						"token": []byte("secrettoken"),
					},
				},
				eventType: "MY_EVENT",
				payload:   ioutil.NopCloser(bytes.NewBufferString("somepayload")),
			},
			wantErr: true,
		}, {
			name:   "nil body does not panic",
			GitHub: &triggersv1.GitHubInterceptor{},
			args: args{
				payload:   nil,
				signature: "foo",
			},
			want:    []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := rtesting.SetupFakeContext(t)
			logger, _ := logging.NewLogger("", "")
			kubeClient := fakekubeclient.Get(ctx)
			request := &http.Request{
				Body: tt.args.payload,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}
			if tt.args.eventType != "" {
				request.Header.Add("X-GITHUB-EVENT", tt.args.eventType)
			}
			if tt.args.signature != "" {
				request.Header.Add("X-Hub-Signature", tt.args.signature)
			}
			if tt.args.secret != nil {
				if _, err := kubeClient.CoreV1().Secrets(metav1.NamespaceDefault).Create(ctx, tt.args.secret, metav1.CreateOptions{}); err != nil {
					t.Error(err)
				}
			}
			w := &Interceptor{
				KubeClientSet:          kubeClient,
				GitHub:                 tt.GitHub,
				Logger:                 logger,
				EventListenerNamespace: metav1.NamespaceDefault,
			}
			resp, err := w.ExecuteTrigger(request)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Interceptor.ExecuteTrigger() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			got, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Interceptor.ExecuteTrigger (-want, +got) = %s", diff)
			}
		})
	}
}

func TestInterceptor_ExecuteTrigger_with_invalid_content_type(t *testing.T) {
	ctx, _ := rtesting.SetupFakeContext(t)
	logger, _ := logging.NewLogger("", "")
	kubeClient := fakekubeclient.Get(ctx)
	request := &http.Request{
		Body: ioutil.NopCloser(bytes.NewBufferString("somepayload")),
		Header: http.Header{
			"Content-Type":    []string{"application/x-www-form-urlencoded"},
			"X-Hub-Signature": []string{"foo"},
		},
	}
	w := &Interceptor{
		KubeClientSet:          kubeClient,
		GitHub:                 &triggersv1.GitHubInterceptor{},
		Logger:                 logger,
		EventListenerNamespace: metav1.NamespaceDefault,
	}
	_, err := w.ExecuteTrigger(request)
	if err != ErrInvalidContentType {
		t.Fatalf("got error %v, want %v", err, ErrInvalidContentType)
	}
}
