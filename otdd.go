// Copyright 2018 Istio Authors
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

// nolint:lll
// Generates the mygrpcadapter adapter's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $REPO_ROOT/bin/mixer_codegen.sh -a mixer/adapter/mygrpcadapter/config/config.proto -x "-s=false -n mygrpcadapter -t metric"

package otddadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	//"istio.io/istio/mixer/adapter/otdd/config"
	"otdd.io/otdd-adapter/config"
	"istio.io/istio/mixer/template/logentry"
	//otdd "istio.io/istio/mixer/adapter/otdd/otddserver"
	otdd "otdd.io/otdd-adapter/otddserver"
	"time"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// OtddAdapter supports metric template.
	OtddAdapter struct {
		listener net.Listener
		server   *grpc.Server
	}
)

var _ logentry.HandleLogEntryServiceServer = &OtddAdapter{}

func (s *OtddAdapter) HandleLogEntry(ctx context.Context, r *logentry.HandleLogEntryRequest) (*v1beta1.ReportResult, error) {

	cfg := &config.Params{}

	if r.AdapterConfig != nil {
		if err := cfg.Unmarshal(r.AdapterConfig.Value); err != nil {
			fmt.Printf("error unmarshalling adapter config: %v", err)
			return nil, err
		}
	}

	fmt.Printf("HandleLogEntry invoked with:\n  Adapter config: %s\n  Instances: %s\n",
		cfg.Addr, r.Instances)

	conn, err := grpc.Dial(cfg.Addr, grpc.WithInsecure())
        if err != nil {
                fmt.Sprintf("cannot connect to otdd server %s err: %v", cfg.Addr,err)
                return nil,err
        }
	defer conn.Close()
        grpcClient := otdd.NewOtddServerServiceClient(conn)

	for _, instance := range r.Instances {
		testCase := decodeValue(instance.Variables["testcase"].Value)
		fmt.Println("testcase: ",testCase)
		ctx, cancel := context.WithTimeout(context.Background(), 3 * time.Second)
        	defer cancel()
        	_,err := grpcClient.SaveTestCase(ctx,&otdd.SaveTestCaseReq{TestCase:testCase.(string)})
		if err != nil {
			fmt.Println("failed to save testcase to otdd server. err: %v", err)
		} else {
			fmt.Println("testcase saved to otdd server")
		}
	}

	return &v1beta1.ReportResult{}, nil
}

func decodeDimensions(in map[string]*policy.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = decodeValue(v.GetValue())
	}
	return out
}

func decodeValue(in interface{}) interface{} {
	switch t := in.(type) {
	case *policy.Value_StringValue:
		return t.StringValue
	case *policy.Value_Int64Value:
		return t.Int64Value
	case *policy.Value_DoubleValue:
		return t.DoubleValue
	default:
		return fmt.Sprintf("%v", in)
	}
}

// Addr returns the listening address of the server
func (s *OtddAdapter) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *OtddAdapter) Run(shutdown chan error) {
	shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *OtddAdapter) Close() error {
	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

func getServerTLSOption(credential, privateKey, caCertificate string) (grpc.ServerOption, error) {
	certificate, err := tls.LoadX509KeyPair(
		credential,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load key cert pair")
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(caCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to read client ca cert: %s", err)
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, fmt.Errorf("failed to append client certs")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// NewOtddAdapter creates a new IBP adapter that listens at provided port.
func NewOtddAdapter(addr string) (Server, error) {
	if addr == "" {
		addr = "18764"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
	if err != nil {
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &OtddAdapter{
		listener: listener,
	}
	fmt.Printf("listening on \"%v\"\n", s.Addr())

	credential := os.Getenv("GRPC_ADAPTER_CREDENTIAL")
	privateKey := os.Getenv("GRPC_ADAPTER_PRIVATE_KEY")
	certificate := os.Getenv("GRPC_ADAPTER_CERTIFICATE")
	if credential != "" {
		so, err := getServerTLSOption(credential, privateKey, certificate)
		if err != nil {
			return nil, err
		}
		s.server = grpc.NewServer(so)
	} else {
		s.server = grpc.NewServer()
	}
	logentry.RegisterHandleLogEntryServiceServer(s.server, s)
	return s, nil
}
