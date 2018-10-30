//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    kafka.go
//: details: vflow kafka producer plugin
//: author:  Mehrdad Arshad Rad
//: date:    02/01/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package producer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/segmentio/kafka-go.v0"
	"gopkg.in/segmentio/kafka-go.v0/gzip"
	"gopkg.in/segmentio/kafka-go.v0/lz4"
	"gopkg.in/segmentio/kafka-go.v0/snappy"
	"gopkg.in/yaml.v2"
)

// Kafka represents kafka producer
type Kafka struct {
	producer *kafka.Writer
	config   Config
	logger   *log.Logger
}

// Config represents kafka configuration
type Config struct {
	run             kafka.WriterConfig
	BootstrapServer string   `yaml:"bootstrap_server" env:"BOOTSTRAP_SERVER"`
	Brokers         []string `yaml:"brokers" env:"BROKERS"`
	ClientID        string   `yaml:"client_id" env:"CLIENT_ID"`
	Compression     string   `yaml:"compression" env:"COMPRESSION"`
	MaxAttempts     int      `yaml:"max_attempts" env:"MAX_ATTEMPTS"`
	QueueSize       int      `yaml:"queue_size" env:"QUEUE_SIZE"`
	BatchSize       int      `yaml:"batch_size" env:"BATCH_SIZE"`
	Keepalive       int      `yaml:"keepalive" env:"KEEPALIVE"`
	IOTimeout       int      `yaml:"connect-timeout" env:"CONNECT_TIMEOUT"`
	RequiredAcks    int      `yaml:"required-acks" env:"REQUIRED_ACKS"`
	TLSCertFile     string   `yaml:"tls-cert" env:"TLS_CERT"`
	TLSKeyFile      string   `yaml:"tls-key" env:"TLS_KEY"`
	CAFile          string   `yaml:"ca-file" env:"CA_FILE"`
	VerifySSL       bool     `yaml:"verify-ssl" env:"VERIFY_SSL"`
}

func (k *Kafka) setup(configFile string, logger *log.Logger) error {
	var err error

	// set default values
	k.config = Config{
		Brokers:      []string{"localhost:9092"},
		ClientID:     "vFlow.Kafka",
		MaxAttempts:  10,
		QueueSize:    10e3,
		BatchSize:    10e2,
		Keepalive:    180,
		IOTimeout:    10,
		RequiredAcks: -1,
		VerifySSL:    true,
	}

	// setup logger
	k.logger = logger

	// load configuration file if available
	if err = k.load(configFile); err != nil {
		logger.Println(err)
	}

	// get env config
	k.loadEnv("VFLOW_KAFKA")

	// lookup bootstrap server
	if k.config.BootstrapServer != "" {
		brokers, err := bootstrapLookup(k.config.BootstrapServer)
		if err != nil {
			k.logger.Printf("error getting bootstrap servers: %v", err)
		} else {
			k.config.Brokers = brokers
		}
	}

	k.logger.Printf("using kafka brokers %v", k.config.Brokers)

	// init kafka configuration
	k.config.run = kafka.WriterConfig{
		Brokers: k.config.Brokers,
		Dialer: &kafka.Dialer{
			ClientID:  k.config.ClientID,
			Timeout:   time.Second * time.Duration(k.config.IOTimeout),
			DualStack: true,
		},
		Balancer:      &kafka.Hash{},
		MaxAttempts:   k.config.MaxAttempts,
		QueueCapacity: k.config.QueueSize,
		BatchSize:     k.config.BatchSize,
		ReadTimeout:   time.Second * time.Duration(k.config.IOTimeout),
		WriteTimeout:  time.Second * time.Duration(k.config.IOTimeout),
		RequiredAcks:  k.config.RequiredAcks,
		Async:         false,
	}

	if tlsConfig := k.tlsConfig(); tlsConfig != nil {
		k.config.run.Dialer.TLS = tlsConfig
		k.logger.Println("Kafka client TLS enabled")
	}

	switch k.config.Compression {
	case "gzip":
		k.config.run.CompressionCodec = gzip.NewCompressionCodec()
	case "lz4":
		k.config.run.CompressionCodec = lz4.NewCompressionCodec()
	case "snappy":
		k.config.run.CompressionCodec = snappy.NewCompressionCodec()
	}

	return err
}

func (k *Kafka) inputMsg(topic string, mCh chan []byte, ec *uint64) {
	var (
		msg []byte
		ok  bool
	)

	k.config.run.Topic = topic
	k.logger.Printf("start producer: Kafka, brokers: %+v, topic: %s\n",
		k.config.run.Brokers, k.config.run.Topic)
	k.producer = kafka.NewWriter(k.config.run)

	for {
		msg, ok = <-mCh
		if !ok {
			break
		}

		err := k.producer.WriteMessages(context.Background(), kafka.Message{
			Value: msg,
		})

		k.logger.Println(err.Error())
	}

	k.producer.Close()
}

func (k *Kafka) load(f string) error {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(b, &k.config)
	if err != nil {
		return err
	}

	return nil
}

func (k Kafka) tlsConfig() *tls.Config {
	var t *tls.Config

	if k.config.TLSCertFile != "" && k.config.TLSKeyFile != "" && k.config.CAFile != "" {
		cert, err := tls.LoadX509KeyPair(k.config.TLSCertFile, k.config.TLSKeyFile)
		if err != nil {
			k.logger.Fatal("Kafka TLS error: ", err)
		}

		caCert, err := ioutil.ReadFile(k.config.CAFile)
		if err != nil {
			k.logger.Fatal("Kafka TLS error: ", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		t = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: !k.config.VerifySSL,
		}
	}

	return t
}

func (k *Kafka) loadEnv(prefix string) {
	v := reflect.ValueOf(&k.config).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		env := t.Field(i).Tag.Get("env")
		if env == "" {
			continue
		}

		val, ok := os.LookupEnv(prefix + "_" + env)
		if !ok {
			continue
		}

		switch f.Kind() {
		case reflect.Int:
			valInt, err := strconv.Atoi(val)
			if err != nil {
				k.logger.Println(err)
				continue
			}
			f.SetInt(int64(valInt))
		case reflect.String:
			f.SetString(val)
		case reflect.Slice:
			for _, elm := range strings.Split(val, ";") {
				f.Index(0).SetString(elm)
			}
		case reflect.Bool:
			valBool, err := strconv.ParseBool(val)
			if err != nil {
				k.logger.Println(err)
				continue
			}
			f.SetBool(valBool)
		}
	}
}

func bootstrapLookup(endpoint string) ([]string, error) {

	var err error
	var brokers []string

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return brokers, err
	}

	addrs, err := net.LookupHost(host)

	if err != nil {
		return brokers, err
	}

	for _, ip := range addrs {
		brokers = append(brokers, strings.Join([]string{ip, port}, ":"))
	}

	return brokers, err
}
