// tools_devices.go implements the MCP devices tool group:
// list_connected_devices and revoke_device. Both are registered for every
// authenticated actor (no role gate: every user has their own connected
// devices/apps to manage) and are ALWAYS self-scoped -- see
// revokeDeviceHandler's doc comment for why this is deliberately stricter
// than the pre-existing REST admin-override behavior for CLI devices.
package mcpserver

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/store"
)

// registerDevicesTools adds the devices tool group for every
// authenticated, non-pending actor.
func (h *Handler) registerDevicesTools(server *mcp.Server, u *store.User) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_connected_devices",
		Description: `List your own connected devices and apps: CLI logins (kind="cli") and OAuth/MCP client connections (kind="oauth").`,
	}, h.listConnectedDevicesHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "revoke_device",
		Description: "Revoke one of your own connected devices or apps by kind+id. Immediately stops future access-token minting from it.",
	}, h.revokeDeviceHandler(u))
}

func deviceInfoResult(d api.DeviceInfo) map[string]any {
	dto := map[string]any{
		"id":         d.ID,
		"kind":       d.Kind,
		"name":       d.Name,
		"created_at": d.CreatedAt,
	}
	if !d.LastUsedAt.IsZero() {
		dto["last_used_at"] = d.LastUsedAt
	} else {
		dto["last_used_at"] = nil
	}
	return dto
}

// listConnectedDevicesOut is list_connected_devices' output.
type listConnectedDevicesOut struct {
	Devices []map[string]any `json:"devices"`
}

func (h *Handler) listConnectedDevicesHandler(u *store.User) mcp.ToolHandlerFor[struct{}, listConnectedDevicesOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listConnectedDevicesOut, error) {
		devices, err := h.api.ListDevices(ctx, u)
		if err != nil {
			return nil, listConnectedDevicesOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(devices))
		for _, d := range devices {
			dtos = append(dtos, deviceInfoResult(d))
		}
		return nil, listConnectedDevicesOut{Devices: dtos}, nil
	}
}

// revokeDeviceIn is revoke_device's input.
type revokeDeviceIn struct {
	Kind string `json:"kind" jsonschema:"\"cli\" or \"oauth\", as returned by list_connected_devices"`
	ID   string `json:"id" jsonschema:"the device/app's id, as returned by list_connected_devices"`
}

// revokeDeviceOut is revoke_device's output.
type revokeDeviceOut struct {
	Revoked bool `json:"revoked"`
}

// revokeDeviceHandler always passes allowAdminOverride=false to
// api.Handler.RevokeDevice, regardless of u's own role: unlike the
// pre-existing REST DELETE /api/v1/me/devices/{id} (which lets an org
// admin revoke ANY user's CLI device), this package's design deliberately
// keeps the devices group "self-scoped" for every actor including admins
// -- an admin's MCP session gets no more reach here than a plain member's
// session would.
func (h *Handler) revokeDeviceHandler(u *store.User) mcp.ToolHandlerFor[revokeDeviceIn, revokeDeviceOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in revokeDeviceIn) (*mcp.CallToolResult, revokeDeviceOut, error) {
		if in.Kind == "" || in.ID == "" {
			return nil, revokeDeviceOut{}, errors.New("kind and id are both required")
		}
		if in.Kind != "cli" && in.Kind != "oauth" {
			return nil, revokeDeviceOut{}, errors.New(`kind must be "cli" or "oauth"`)
		}
		if err := h.api.RevokeDevice(ctx, u, in.Kind, in.ID, false); err != nil {
			return nil, revokeDeviceOut{}, toolError(err)
		}
		return nil, revokeDeviceOut{Revoked: true}, nil
	}
}
