package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
	"github.com/en3sis/rackpulse/agent/internal/history"
	"github.com/en3sis/rackpulse/agent/internal/pairing"
)

func Run(version string) error {
	log.SetFlags(0)
	cfg, err := config.Load(config.Path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if created, err := pairing.EnsureCertificate(config.CertPath, config.KeyPath); err != nil {
		return fmt.Errorf("create TLS certificate: %w", err)
	} else if created {
		log.Printf("Created a new TLS certificate")
	}
	certificate, fingerprint, err := pairing.LoadCertificate(config.CertPath, config.KeyPath)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	now := time.Now().Unix()
	host, err := history.LoadHost(config.HistoryPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("Starting a new history, the old one could not be read: %v", err)
		}
		host = history.NewHost(now)
	}
	if boot, err := collect.BootTime(); err == nil && boot > 0 {
		host.MarkRange(boot, now, now)
		host.LowerCoverageStart(max(boot, now-history.RetentionSeconds))
	}
	host.Prune(now)
	containers, err := history.LoadContainers(config.ContainersPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("Starting a new container history, the old one could not be read: %v", err)
		}
		containers = history.NewContainers()
	}
	containers.Prune(now)

	listener, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Address(), err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	collector := collect.New(version, cfg.TailscaleName)
	go collector.Run(ctx, func(snapshot collect.Snapshot) {
		host.AddSample(history.SampleFrom(snapshot), snapshot.Time)
		if snapshot.Docker != nil && snapshot.Docker.Error == nil {
			containers.Record(snapshot.Docker.Containers, snapshot.Time)
		}
	})
	go markMinutes(ctx, host)
	go saveLoop(ctx, host, containers)

	server := &http.Server{
		Handler: &handler{
			version:     version,
			token:       cfg.Token,
			fingerprint: fingerprint,
			collector:   collector,
			host:        host,
			containers:  containers,
		},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	log.Printf("rackpulse-agent %s listening on %s", version, listener.Addr())

	served := make(chan error, 1)
	go func() { served <- server.ServeTLS(listener, "", "") }()

	select {
	case err := <-served:
		save(host, containers)
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	host.MarkMinute(time.Now().Unix())
	save(host, containers)
	log.Printf("Stopped")
	return nil
}

func markMinutes(ctx context.Context, host *history.Host) {
	host.MarkMinute(time.Now().Unix())
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			host.MarkMinute(now.Unix())
		}
	}
}

func save(host *history.Host, containers *history.Containers) {
	now := time.Now().Unix()
	host.Prune(now)
	if err := host.Save(config.HistoryPath); err != nil {
		log.Printf("Saving history failed: %v", err)
	}
	containers.Prune(now)
	if err := containers.Save(config.ContainersPath); err != nil {
		log.Printf("Saving container history failed: %v", err)
	}
}

func saveLoop(ctx context.Context, host *history.Host, containers *history.Containers) {
	save(host, containers)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			save(host, containers)
		}
	}
}
