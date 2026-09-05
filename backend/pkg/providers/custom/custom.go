package custom

import (
	"context"
	"os"
	"strings"
	"sync/atomic"

	"pentagi/pkg/config"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/system"
	"pentagi/pkg/templates"

	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/openai"
	"github.com/vxcontrol/langchaingo/llms/streaming"
	"gopkg.in/yaml.v3"
)

func BuildProviderConfig(cfg *config.Config, configData []byte) (*pconfig.ProviderConfig, error) {
	defaultOptions := []llms.CallOption{
		llms.WithTemperature(1.0),
		llms.WithTopP(1.0),
		llms.WithN(1),
		llms.WithMaxTokens(16384),
	}

	if cfg.LLMServerModel != "" {
		defaultOptions = append(defaultOptions, llms.WithModel(cfg.LLMServerModel))
	}

	providerConfig, err := pconfig.LoadConfigData(configData, defaultOptions)
	if err != nil {
		return nil, err
	}

	return providerConfig, nil
}

func DefaultProviderConfig(cfg *config.Config) (*pconfig.ProviderConfig, error) {
	if cfg.LLMServerConfig == "" {
		return BuildProviderConfig(cfg, []byte(pconfig.EmptyProviderConfigRaw))
	}

	configData, err := os.ReadFile(cfg.LLMServerConfig)
	if err != nil {
		return nil, err
	}

	return BuildProviderConfig(cfg, configData)
}

type customProvider struct {
	clients        []*openai.LLM
	next           atomic.Uint64
	model          string
	models         pconfig.ModelsConfig
	providerName   provider.ProviderName
	providerConfig *pconfig.ProviderConfig
	providerPrefix string
}

// maxKeyFailoverAttempts caps how many pool keys a single non-streaming call
// will try before giving up (prevents stalling when the whole pool is down).
const maxKeyFailoverAttempts = 5

// retryableKeyError reports whether err looks like a per-key quota/auth/
// capacity problem worth retrying with the next pooled key.
func retryableKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"429", "rate limit", "rate_limit", "ratelimit", "too many requests",
		"401", "403", "forbidden", "unauthorized", "invalid api key", "incorrect api key",
		"overloaded", "capacity", "insufficient", "quota", "402",
		"500", "502", "503", "529",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// client returns the next pooled LLM client (round-robin), spreading quota
// usage across all configured keys.
func (p *customProvider) client() *openai.LLM {
	n := uint64(len(p.clients))
	if n == 0 {
		return nil
	}
	return p.clients[p.next.Add(1)%n]
}

// customEndpointOverride allows a saved (user) custom provider to point at its
// own OpenAI-compatible endpoint instead of the global LLM_SERVER_* settings,
// optionally with a pool of API keys that are used round-robin with failover
// (e.g. many free-tier gateway keys behind one provider name).
// Stored as top-level keys in the provider's config JSON; absent keys fall
// back to the globals, so file-based configs keep working unchanged.
type customEndpointOverride struct {
	BaseURL string   `json:"base_url" yaml:"base_url"`
	APIKey  string   `json:"api_key" yaml:"api_key"`
	APIKeys []string `json:"api_keys" yaml:"api_keys"`
	Model   string   `json:"model" yaml:"model"`
}

// resolveEndpoint returns the effective base URL, API keys and default model:
// per-provider overrides from the stored raw config when present, globals
// otherwise. The returned keys slice always has at least one entry.
func resolveEndpoint(cfg *config.Config, providerConfig *pconfig.ProviderConfig) (string, []string, string) {
	baseURL, baseModel := cfg.LLMServerURL, cfg.LLMServerModel
	keys := []string{cfg.LLMServerKey}
	if providerConfig == nil {
		return baseURL, keys, baseModel
	}
	var override customEndpointOverride
	if err := yaml.Unmarshal(providerConfig.GetRawConfig(), &override); err != nil {
		return baseURL, keys, baseModel
	}
	if override.BaseURL != "" {
		baseURL = override.BaseURL
	}
	// api_keys (pool) wins over api_key (single) when both are present.
	switch {
	case len(override.APIKeys) > 0:
		keys = override.APIKeys
	case override.APIKey != "":
		keys = []string{override.APIKey}
	}
	if override.Model != "" {
		baseModel = override.Model
	}
	return baseURL, keys, baseModel
}

func New(
	cfg *config.Config,
	providerName provider.ProviderName,
	providerConfig *pconfig.ProviderConfig,
) (provider.Provider, error) {
	baseKey := cfg.LLMServerKey
	baseURL := cfg.LLMServerURL
	baseModel := cfg.LLMServerModel
	baseKeys := []string{baseKey}
	// A saved user provider may carry its own endpoint and key pool (e.g. a
	// second gateway like Kilo alongside the default OpenRouter one).
	if providerConfig != nil {
		baseURL, baseKeys, baseModel = resolveEndpoint(cfg, providerConfig)
		baseKey = baseKeys[0]
	}
	httpClient, err := system.GetHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	opts := []openai.Option{
		openai.WithToken(baseKey),
		openai.WithModel(baseModel),
		openai.WithBaseURL(baseURL),
		openai.WithHTTPClient(httpClient),
	}
	if !cfg.LLMServerLegacyReasoning {
		opts = append(opts,
			openai.WithUsingReasoningMaxTokens(),
			openai.WithModernReasoningFormat(),
		)
	}
	if cfg.LLMServerPreserveReasoning {
		opts = append(opts,
			openai.WithPreserveReasoningContent(),
		)
	}
	// One client per pooled key; calls rotate across them (see client()).
	clients := make([]*openai.LLM, 0, len(baseKeys))
	for _, key := range baseKeys {
		keyOpts := make([]openai.Option, len(opts))
		copy(keyOpts, opts)
		keyOpts[0] = openai.WithToken(key)
		client, err := openai.New(keyOpts...)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	models, err := provider.LoadModelsFromHTTP(baseURL, baseKey, httpClient, cfg.LLMServerProvider)
	if err != nil {
		models = pconfig.ModelsConfig{}
	}

	return &customProvider{
		clients:        clients,
		model:          baseModel,
		models:         models,
		providerName:   providerName,
		providerConfig: providerConfig,
		providerPrefix: cfg.LLMServerProvider,
	}, nil
}

func (p *customProvider) Type() provider.ProviderType {
	return provider.ProviderCustom
}

func (p *customProvider) Name() provider.ProviderName {
	return p.providerName
}

func (p *customProvider) GetRawConfig() []byte {
	return p.providerConfig.GetRawConfig()
}

func (p *customProvider) GetProviderConfig() *pconfig.ProviderConfig {
	return p.providerConfig
}

func (p *customProvider) GetPriceInfo(opt pconfig.ProviderOptionsType) *pconfig.PriceInfo {
	return p.providerConfig.GetPriceInfoForType(opt)
}

func (p *customProvider) GetModels() pconfig.ModelsConfig {
	return p.models
}

func (p *customProvider) Model(opt pconfig.ProviderOptionsType) string {
	model := p.model
	opts := llms.CallOptions{Model: &model}
	for _, option := range p.providerConfig.GetOptionsForType(opt) {
		option(&opts)
	}

	return opts.GetModel()
}

func (p *customProvider) ModelWithPrefix(opt pconfig.ProviderOptionsType) string {
	return provider.ApplyModelPrefix(p.Model(opt), p.providerPrefix)
}

func (p *customProvider) Call(
	ctx context.Context,
	opt pconfig.ProviderOptionsType,
	prompt string,
) (string, error) {
	// Non-streaming: rotate keys and fail over to the next key on
	// quota/auth/capacity errors, so one exhausted key never kills the call.
	attempts := len(p.clients)
	if attempts > maxKeyFailoverAttempts {
		attempts = maxKeyFailoverAttempts
	}
	var err error
	var result string
	for i := 0; i < attempts; i++ {
		result, err = provider.WrapGenerateFromSinglePrompt(
			ctx, p, opt, p.client(), prompt,
			p.providerConfig.GetOptionsForType(opt)...,
		)
		if err == nil || !retryableKeyError(err) {
			return result, err
		}
	}
	return result, err
}

func (p *customProvider) CallEx(
	ctx context.Context,
	opt pconfig.ProviderOptionsType,
	chain []llms.MessageContent,
	streamCb streaming.Callback,
) (*llms.ContentResponse, error) {
	return provider.WrapGenerateContent(
		ctx, p, opt, p.client().GenerateContent, chain,
		append([]llms.CallOption{
			llms.WithStreamingFunc(streamCb),
		}, p.providerConfig.GetOptionsForType(opt)...)...,
	)
}

func (p *customProvider) CallWithTools(
	ctx context.Context,
	opt pconfig.ProviderOptionsType,
	chain []llms.MessageContent,
	tools []llms.Tool,
	streamCb streaming.Callback,
) (*llms.ContentResponse, error) {
	return provider.WrapGenerateContent(
		ctx, p, opt, p.client().GenerateContent, chain,
		append([]llms.CallOption{
			llms.WithTools(tools),
			llms.WithStreamingFunc(streamCb),
		}, p.providerConfig.GetOptionsForType(opt)...)...,
	)
}

// CallWithExtraOptions: extra is appended last, so it overrides the config.
func (p *customProvider) CallWithExtraOptions(
	ctx context.Context,
	opt pconfig.ProviderOptionsType,
	chain []llms.MessageContent,
	tools []llms.Tool,
	streamCb streaming.Callback,
	extra ...llms.CallOption,
) (*llms.ContentResponse, error) {
	options := []llms.CallOption{llms.WithStreamingFunc(streamCb)}
	if len(tools) > 0 {
		options = append(options, llms.WithTools(tools))
	}
	options = append(options, p.providerConfig.GetOptionsForType(opt)...)
	options = append(options, extra...)

	return provider.WrapGenerateContent(ctx, p, opt, p.client().GenerateContent, chain, options...)
}

func (p *customProvider) GetUsage(info map[string]any) pconfig.CallUsage {
	return pconfig.NewCallUsage(info)
}

func (p *customProvider) GetToolCallIDTemplate(ctx context.Context, prompter templates.Prompter) (string, error) {
	return provider.DetermineToolCallIDTemplate(ctx, p, pconfig.OptionsTypeSimple, prompter, "")
}
