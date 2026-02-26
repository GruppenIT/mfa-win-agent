package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/auth"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/certs"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/events"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/heartbeat"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/logging"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/radius"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/mfa-gruppen/radius-agent.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mfa-gruppen-radius-agent %s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	logging.Setup(cfg.Logging.Level, cfg.Logging.Format)
	slog.Info("starting mfa-gruppen-radius-agent", "version", version)

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})

	// Initialize event reporter
	reporter := events.NewReporter(cfg.API.BaseURL, cfg.API.Key, cfg.Server.AgentID)
	reporter.Start(ctx)
	defer reporter.Stop()

	// Initialize shared TOTP validator
	totpVal := auth.NewTOTPValidator(cfg.API.BaseURL, cfg.API.Key, cfg.API.Timeout)

	// Initialize heartbeat counters
	counters := &heartbeat.Counters{}

	var wg sync.WaitGroup

	// Start RADIUS module
	var radiusServer *radius.Server
	if cfg.RADIUS.Enabled {
		var ldapAuth *auth.LDAPAuthenticator
		if cfg.RADIUS.LDAP != nil {
			ldapAuth = auth.NewLDAPAuthenticator(cfg.RADIUS.LDAP)
		}

		radiusServer = radius.NewServer(cfg.RADIUS.Port, cfg.RADIUS.Secret, totpVal, ldapAuth, reporter)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := radiusServer.Start(ctx); err != nil {
				slog.Error("RADIUS server error", "error", err)
			}
		}()
		slog.Info("RADIUS module enabled", "port", cfg.RADIUS.Port)
	} else {
		slog.Info("RADIUS module disabled")
	}

	// Start IdP module
	var idpServer *idp.Server
	if cfg.IdP.Enabled {
		// Ensure TLS certificates
		if err := certs.EnsureCertificates(cfg.IdP.TLS.Cert, cfg.IdP.TLS.Key, cfg.IdP.TLS.AutoGenerate); err != nil {
			slog.Error("certificate setup failed", "error", err)
			os.Exit(1)
		}

		cert, err := certs.LoadCertificate(cfg.IdP.TLS.Cert)
		if err != nil {
			slog.Error("failed to load certificate", "error", err)
			os.Exit(1)
		}
		key, err := certs.LoadPrivateKey(cfg.IdP.TLS.Key)
		if err != nil {
			slog.Error("failed to load private key", "error", err)
			os.Exit(1)
		}

		// Resolve LDAP config
		ldapCfg := cfg.ResolveLDAP()
		if ldapCfg == nil {
			slog.Error("LDAP configuration required for IdP module")
			os.Exit(1)
		}
		ldapAuth := auth.NewLDAPAuthenticator(ldapCfg)

		idpServer, err = idp.NewServer(&cfg.IdP, cert, key, ldapAuth, totpVal, reporter)
		if err != nil {
			slog.Error("failed to create IdP server", "error", err)
			os.Exit(1)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := idpServer.Start(ctx, done); err != nil {
				slog.Error("IdP server error", "error", err)
			}
		}()
		slog.Info("IdP module enabled", "port", cfg.IdP.Port, "entity_id", cfg.IdP.EntityID)
	} else {
		slog.Info("IdP module disabled")
	}

	// Start heartbeat
	idpStatusFn := func() heartbeat.IdPStatus {
		if idpServer != nil {
			return heartbeat.IdPStatus{
				Active:      cfg.IdP.Enabled,
				Port:        cfg.IdP.Port,
				CertValidTo: idpServer.CertNotAfter().Format(time.RFC3339),
			}
		}
		return heartbeat.IdPStatus{Active: false}
	}
	sessionCountFn := func() int {
		if idpServer != nil {
			return idpServer.Sessions().ActiveCount()
		}
		return 0
	}
	hb := heartbeat.NewSender(cfg.API.BaseURL, cfg.API.Key, cfg.Server.AgentID, 300, counters, idpStatusFn, sessionCountFn)
	wg.Add(1)
	go func() {
		defer wg.Done()
		hb.Start(ctx)
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("shutdown signal received", "signal", sig)

	// Graceful shutdown
	close(done)
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if idpServer != nil {
		if err := idpServer.Stop(shutdownCtx); err != nil {
			slog.Error("IdP shutdown error", "error", err)
		}
	}
	if radiusServer != nil {
		if err := radiusServer.Stop(); err != nil {
			slog.Error("RADIUS shutdown error", "error", err)
		}
	}

	wg.Wait()
	slog.Info("agent stopped")
}
