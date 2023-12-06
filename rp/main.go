package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/exp/slog"
)

var (
	callbackPath = "/cb"
	key          = []byte("01234567890123456789012345678901")
)

func createOIDCClientWithRetry(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, scopes []string, options ...rp.Option) (rp.RelyingParty, error) {
	maxRetries := 5
	retryInterval := time.Second * 5

	for i := 0; i < maxRetries; i++ {
		provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
		if err != nil {
			logrus.Errorf("error creating oidc client: %v", err)
			time.Sleep(retryInterval)
			continue
		}
		return provider, nil
	}
	return nil, fmt.Errorf("failed to create oidc client after %d attempts", maxRetries)
}

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := "http://localhost:8080/realms/demo"
	port := "3000"
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}),
	)
	client := &http.Client{
		Timeout: time.Minute,
	}

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		rp.WithLogger(logger),
	}

	ctx := logging.ToContext(context.TODO(), logger)
	provider, err := createOIDCClientWithRetry(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating oidc client: %v", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	http.Handle("/login", rp.AuthURLHandler(state, provider))

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
	http.Handle(callbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider))

	var counter atomic.Int64

	mw := logging.Middleware(
		logging.WithLogger(logger),
		logging.WithGroup("server"),
		logging.WithIDFunc(func() slog.Attr {
			return slog.Int64("request_id", counter.Add(1))
		}),
	)

	lis := fmt.Sprintf("0.0.0.0:%s", port)
	logger.Info("starting server on ", lis)
	err = http.ListenAndServe(lis, mw(http.DefaultServeMux))
	if err != http.ErrServerClosed {
		logger.Error("error starting server: ", err)
		os.Exit(1)
	}
}
