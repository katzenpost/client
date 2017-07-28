// main.go - mixnet client
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package main provides a mixnet client daemon
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)
var ttyFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

const ioctlReadTermios = 0x5401

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

func stringToLogLevel(level string) (logging.Level, error) {

	switch level {
	case "DEBUG":
		return logging.DEBUG, nil
	case "INFO":
		return logging.INFO, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "WARNING":
		return logging.WARNING, nil
	case "ERROR":
		return logging.ERROR, nil
	case "CRITICAL":
		return logging.CRITICAL, nil
	}
	return -1, fmt.Errorf("invalid logging level %s", level)
}

func setupLoggerBackend(level logging.Level) logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(level, "mixclient")
	return leveler
}

func main() {
	var err error
	var config *Config
	var level logging.Level

	var configFilePath string
	var logLevel string
	var shouldAutogenKeys bool

	flag.BoolVar(&shouldAutogenKeys, "autogenkeys", false, "auto-generate cryptographic keys specified in configuration file")
	flag.StringVar(&configFilePath, "config", "", "configuration file")
	flag.StringVar(&logLevel, "log_level", "INFO", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	passphrase := os.Getenv("MIX_CLIENT_VAULT_PASSPHRASE")
	if len(passphrase) == 0 {
		panic("Aborting because bash env var not set: MIX_CLIENT_VAULT_PASSPHRASE")
	}

	if configFilePath == "" {
		log.Error("you must specify a configuration file")
		flag.Usage()
		os.Exit(1)
	}

	tomlConfig, err := LoadConfig(configFilePath)
	if err != nil {
		panic(err)
	}

	level, err = stringToLogLevel(logLevel)
	if err != nil {
		log.Critical("Invalid logging-level specified.")
		os.Exit(1)
	}
	logBackend := setupLoggerBackend(level)
	log.SetBackend(logBackend)

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	if shouldAutogenKeys == true {
		// XXX todo: autogen keys
	}

	config, err = tomlConfig.Config(passphrase)
	if err != nil {
		panic(err)
	}

	log.Notice("mixclient startup")
	client := NewClientDaemon(config)
	client.Start()

	defer client.Stop()
	for {
		select {
		case <-sigKillChan:
			log.Notice("mixclient shutdown")
			return
		}
	}
}
