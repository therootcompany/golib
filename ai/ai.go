package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type API interface {
	Type() string
	Model() string
	WithModel(name string) API
	Generate(system, prompt string, ctx json.RawMessage) (string, error)
}

// ollama show --parameters gpt-oss:20b
// ollama show --parameters qwen3-coder:30b
// var modelName = "gemma3:270m"
// var modelName = "qwen2.5-coder:0.5b"
// var modelName = "qwen3:8b"
// var modelName = "qwen3:30b"
// var modelName = "qwen3-coder:30b"
// var modelName = "gpt-oss:20b"
// var ollamaBaseURL = "http://localhost:11434"
type OllamaAPI struct {
	BaseURL   string
	APIKey    string
	BasicAuth BasicAuth
	ModelName string
}

type BasicAuth struct {
	Username string
	Password string
}

func (a *OllamaAPI) Type() string {
	return "ollama"
}

func (a *OllamaAPI) Model() string {
	return a.ModelName
}

func (a *OllamaAPI) WithModel(model string) API {
	a2 := *a
	a2.ModelName = model
	return &a2
}

func (a *OllamaAPI) Generate(system, prompt string, ctxU32s json.RawMessage) (string, error) {
	var context []uint32
	// for type safety while maintaining interface
	if err := json.Unmarshal(ctxU32s, &context); err != nil {
		return "", err
	}
	reqBody := OllamaGenerate{
		Model:   a.ModelName,
		System:  system,
		Context: context,
		Prompt:  prompt,
		Stream:  false,
		// Options: &Options{
		// 	Temperature: 0.7, // Controls randomness (0.0 to 1.0)
		// 	TopP:        0.8, // Controls diversity (0.0 to 1.0)
		// },
	}

	jsonData, _ := json.Marshal(reqBody)

	apiURL := a.BaseURL + "/api/generate"
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("creating Ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(a.APIKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
	}
	if len(a.BasicAuth.Password) > 0 {
		req.SetBasicAuth(a.BasicAuth.Username, a.BasicAuth.Password)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending Ollama request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("parsing Ollama response: %s %w\n Headers: %#v\n Body: %s", resp.Status, err, resp.Header, body)
	}

	return ollamaResp.Response, nil
}

// var gptModel = "gpt-4o"
// var openAIBaseURL = "https://api.openai.com/v1"
type OpenAiAPI struct {
	BaseURL   string
	APIKey    string
	ModelName string
}

func (a *OpenAiAPI) Type() string {
	return "openai"
}

func (a *OpenAiAPI) Model() string {
	return a.ModelName
}

// https://ollama.readthedocs.io/en/api/#parameters
type OllamaGenerate struct {
	Model  string   `json:"model"`
	Prompt string   `json:"prompt"`
	Suffix string   `json:"suffix"`
	Images []string `json:"images"` // base64
	// "Advanced"
	Format   string   `json:"format"` // "json"
	Context  []uint32 `json:"context"`
	Options  *Options `json:"options,omitempty"`
	System   string   `json:"system"`
	Template string   `json:"template"`
	Stream   bool     `json:"stream"`
	Raw      bool     `json:"raw"`
}

// https://ollama.readthedocs.io/en/api/#parameters
type OllamaInit struct {
	Model     string `json:"model"`
	KeepAlive string `json:"keep_alive"`
}

type Options struct {
	Seed        int     `json:"seed,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	TopP        float64 `json:"top_p,omitempty"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type OpenAIRequest struct {
	Model       string          `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Stream      bool            `json:"stream"`
	ContextSize int             `json:"num_ctx,omitempty,omitzero"`
	Temperature float64         `json:"temperature,omitempty"`
	TopP        float64         `json:"top_p,omitempty"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (a *OpenAiAPI) WithModel(model string) API {
	a2 := *a
	a2.ModelName = model
	return &a2
}

func (a *OpenAiAPI) Generate(system, prompt string, ctxMessages json.RawMessage) (string, error) {
	reqBody := OpenAIRequest{
		Model: a.ModelName, // Default OpenAI model, adjust as needed
		Messages: []OpenAIMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: prompt},
		},
		Stream: false,
		// Temperature: 0.7,
		// TopP:        0.9,
	}

	jsonData, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", a.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("creating OpenAI request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending OpenAI request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var openAIResp OpenAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return "", fmt.Errorf("parsing OpenAI response: %w, body: %s", err, body)
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in OpenAI response")
	}

	return openAIResp.Choices[0].Message.Content, nil
}

// interface guards
var _ API = (*OllamaAPI)(nil)
var _ API = (*OpenAiAPI)(nil)
