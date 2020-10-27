package api

import (
	"context"

	meta_schema "github.com/open-rpc/meta-schema"
)

// RPCSystemExtension provides system extension RPC services.
type RPCSystemExtension interface {
	Discover(context.Context) (*meta_schema.OpenrpcDocument, error)
}
