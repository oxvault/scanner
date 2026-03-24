package engines

import (
	"fmt"
	"log/slog"

	"github.com/oxvault/scanner/providers"
)

// PinReport holds the results of a pin check
type PinReport struct {
	Diffs   []providers.PinDiff
	Changed bool
}

// PinEngine handles tool description pinning and rug pull detection
type PinEngine interface {
	Pin(cmd string, args []string) (int, error)
	Check(cmd string, args []string) (*PinReport, error)
}

type pinner struct {
	mcpClient providers.MCPClient
	pinStore  providers.PinStore
	logger    *slog.Logger
}

func NewPinner(
	mcpClient providers.MCPClient,
	pinStore providers.PinStore,
	logger *slog.Logger,
) PinEngine {
	return &pinner{
		mcpClient: mcpClient,
		pinStore:  pinStore,
		logger:    logger,
	}
}

func (p *pinner) Pin(cmd string, args []string) (int, error) {
	session, err := p.mcpClient.Connect(cmd, args)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer p.mcpClient.Close(session)

	tools, err := p.mcpClient.ListTools(session)
	if err != nil {
		return 0, fmt.Errorf("list tools: %w", err)
	}

	if err := p.pinStore.Pin(tools); err != nil {
		return 0, fmt.Errorf("store pins: %w", err)
	}

	p.logger.Info("tools pinned", "count", len(tools))
	return len(tools), nil
}

func (p *pinner) Check(cmd string, args []string) (*PinReport, error) {
	session, err := p.mcpClient.Connect(cmd, args)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer p.mcpClient.Close(session)

	tools, err := p.mcpClient.ListTools(session)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	diffs, err := p.pinStore.Check(tools)
	if err != nil {
		return nil, err
	}

	report := &PinReport{Diffs: diffs}
	for _, d := range diffs {
		if d.Changed {
			report.Changed = true
			break
		}
	}

	return report, nil
}
